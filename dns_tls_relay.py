#!/usr/bin/env python3

import os
import time
import threading
import socket
import select
import heapq

from random import randint
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

import basic_tools as tools

from dns_tls_constants import *

from basic_tools import Log
from advanced_tools import relay_queue

from dns_tls_protocols import TLSRelay, Reachability
from dns_tls_packets import ClientRequest, ttl_rewrite

__all__ = (
    'DNSRelay'
)


class RateLimiter:
    '''simple token bucket rate limiter per client IP.'''
    __slots__ = ('_tokens', '_last_refill', '_rate', '_burst', '_lock')

    def __init__(self, rate=50, burst=100):
        self._tokens = defaultdict(lambda: burst)
        self._last_refill = defaultdict(fast_time)
        self._rate = rate
        self._burst = burst
        self._lock = threading.Lock()

    def allow(self, client_ip):
        with self._lock:
            now = fast_time()
            last = self._last_refill[client_ip]
            elapsed = now - last
            self._tokens[client_ip] = min(self._burst, self._tokens[client_ip] + elapsed * self._rate)
            self._last_refill[client_ip] = now

            if self._tokens[client_ip] >= 1:
                self._tokens[client_ip] -= 1
                return True
            return False

    def cleanup(self):
        now = fast_time()
        with self._lock:
            stale = [ip for ip, last in list(self._last_refill.items()) if now - last > 60]
            for ip in stale:
                del self._tokens[ip]
                del self._last_refill[ip]


class Metrics:
    '''simple query metrics counter.'''
    __slots__ = ('_lock', '_total', '_cached', '_negative_hits', '_errors', '_by_type', '_start_time')

    def __init__(self):
        self._lock = threading.Lock()
        self._total = 0
        self._cached = 0
        self._negative_hits = 0
        self._errors = 0
        self._by_type = Counter()
        self._start_time = fast_time()

    def record_query(self, qtype):
        with self._lock:
            self._total += 1
            self._by_type[DNS(qtype).name if qtype in iter(DNS) else str(qtype)] += 1

    def record_cache_hit(self):
        with self._lock:
            self._cached += 1

    def record_negative_hit(self):
        with self._lock:
            self._negative_hits += 1

    def record_error(self):
        with self._lock:
            self._errors += 1

    def snapshot(self):
        with self._lock:
            uptime = fast_time() - self._start_time
            return {
                'uptime': uptime,
                'total_queries': self._total,
                'cached_responses': self._cached,
                'negative_hits': self._negative_hits,
                'errors': self._errors,
                'by_type': dict(self._by_type),
                'cache_hit_ratio': round(self._cached / max(self._total, 1), 3),
            }


class DNSRelay:
    protocol = PROTO.DNS_TLS

    # flag used to check status of relay. if one remote server is up, tls_up=True. both remote servers have to be down
    # for tls_up=False.
    tls_up = False
    keepalive_interval = 0
    keepalive_domain = KEEP_ALIVE_DOMAIN

    dns_servers = DNS_SERVERS(
        {'ip': None, PROTO.DNS_TLS: False},
        {'ip': None, PROTO.DNS_TLS: False}
    )

    _executor = None
    _max_workers = 32
    _epoll = None
    _registered_socks = {}
    _socks_lock = threading.Lock()
    _request_map = {}
    _id_lock = threading.Lock()
    _exec_lock = threading.Lock()

    _shutdown_event = threading.Event()

    _rate_limiter = RateLimiter()
    _dnssec_enabled = False
    _metrics_port = 9190
    _metrics = Metrics()

    @classmethod
    def _get_executor(cls):
        with cls._exec_lock:
            if (cls._executor is None):
                cls._executor = ThreadPoolExecutor(max_workers=min(cls._max_workers, (os.cpu_count() or 1) + 4))
        return cls._executor

    def __init__(self):
        t = threading.Thread(target=self.responder)
        t.daemon = True
        t.start()

        # assigning object methods to prevent lookup
        self._request_map_pop = self._request_map.pop

        self._records_cache_add = self._records_cache.add
        self._records_cache_search = self._records_cache.search
        self._records_cache_note_lookup = self._records_cache.note_lookup

    @classmethod
    def shutdown(cls):
        Log.system('Shutting down DNS Relay...')

        cls._shutdown_event.set()

        if hasattr(cls, '_records_cache'):
            if cls._records_cache._persist:
                top_domains = cls._records_cache._rank_top_domains()
                if top_domains:
                    tools.write_cache(top_domains)

            try:
                cls._records_cache._negative_cache.clear()
            except AttributeError:
                pass

        if hasattr(cls, '_epoll'):
            try:
                cls._epoll.close()
            except OSError:
                pass

        with cls._socks_lock:
            for fd, l_sock in list(cls._registered_socks.items()):
                try:
                    l_sock.socket.close()
                except OSError:
                    pass
            cls._registered_socks.clear()

        Log.system('DNS Relay shutdown complete.')

    @classmethod
    def run(cls, listening_addresses, keepalive_interval, persist_top_domains=True):
        Log.system('Initializing primary service...')

        cls.keepalive_interval = keepalive_interval
        cls._epoll = select.epoll()

        # running main epoll/ socket loop. threaded so proxy and server can run side by side
        # NOTE: threading.Thread(target=service_loop._listener).start() starting a registration thread for all available
        # interfaces. once registered the threads will exit.
        for ip_addr in listening_addresses:
            t = threading.Thread(target=cls._register, args=(f'{ip_addr}',))
            t.daemon = True
            t.start()

        Reachability.run(cls)
        TLSRelay.run(cls)

        # initializing dns cache/ sending in reference to needed methods for top domains
        cls._records_cache = DNSCache(
            dns_packet=ClientRequest.generate_local_query,
            request_handler=cls._handle_query,
            persist=persist_top_domains
        )

        t = threading.Thread(target=cls()._listener)
        t.daemon = True
        t.start()

        t = threading.Thread(target=cls._clean_orphaned_ids)
        t.daemon = True
        t.start()

        t = threading.Thread(target=cls._rate_limiter_cleanup)
        t.daemon = True
        t.start()

        t = threading.Thread(target=cls._metrics_server)
        t.daemon = True
        t.start()

    @classmethod
    @tools.looper(FIVE_MIN)
    def _rate_limiter_cleanup(cls):
        cls._rate_limiter.cleanup()

    @classmethod
    def _metrics_server(cls):
        '''simple HTTP metrics endpoint on port 9090 (Prometheus text format).'''
        port = cls._metrics_port
        metrics_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        metrics_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            metrics_sock.bind(('127.0.0.1', port))
            metrics_sock.listen(5)
            metrics_sock.settimeout(1)
        except OSError:
            Log.verbose(f'[metrics] port {port} unavailable, metrics disabled')
            return

        Log.system(f'[metrics] listening on 127.0.0.1:{port}')

        while not cls._shutdown_event.is_set():
            try:
                conn, _ = metrics_sock.accept()
                with conn:
                    conn.settimeout(5)
                    data = conn.recv(1024)

                    # basic HTTP request validation: only respond to GET /metrics
                    if (not data.startswith(b'GET /metrics ')):
                        conn.sendall(b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')
                        continue

                    stats = cls._metrics.snapshot()
                    body = (
                        '# HELP dns_relay_queries_total Total DNS queries received\n'
                        f'# TYPE dns_relay_queries_total counter\n'
                        f'dns_relay_queries_total {stats["total_queries"]}\n'
                        '# HELP dns_relay_cached_responses Total cached responses served\n'
                        f'# TYPE dns_relay_cached_responses counter\n'
                        f'dns_relay_cached_responses {stats["cached_responses"]}\n'
                        '# HELP dns_relay_negative_hits Total negative cache hits\n'
                        f'# TYPE dns_relay_negative_hits counter\n'
                        f'dns_relay_negative_hits {stats["negative_hits"]}\n'
                        '# HELP dns_relay_errors Total processing errors\n'
                        f'# TYPE dns_relay_errors counter\n'
                        f'dns_relay_errors {stats["errors"]}\n'
                        '# HELP dns_relay_cache_hit_ratio Cache hit ratio\n'
                        f'# TYPE dns_relay_cache_hit_ratio gauge\n'
                        f'dns_relay_cache_hit_ratio {stats["cache_hit_ratio"]}\n'
                        '# HELP dns_relay_uptime_seconds Uptime in seconds\n'
                        f'# TYPE dns_relay_uptime_seconds counter\n'
                        f'dns_relay_uptime_seconds {int(stats["uptime"])}\n'
                    )
                    conn.sendall(b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' + body.encode())
            except socket.timeout:
                continue
            except OSError:
                break

        metrics_sock.close()

    @classmethod
    def _register(cls, listener_ip):
        '''will register interface with listener. requires subclass property for listener_sock returning valid socket
         object. once registration is complete the thread will exit.'''

        Log.system(f'[{listener_ip}] Started registration.')

        l_sock = cls._listener_sock(listener_ip)
        with cls._socks_lock:
            cls._epoll.register(l_sock.fileno(), select.EPOLLIN)
            cls._registered_socks[l_sock.fileno()] = L_SOCK(listener_ip, l_sock, l_sock.sendto, l_sock.recvfrom)

        Log.system(f'[{listener_ip}][{l_sock.fileno()}] Listener registered.')

    def _listener(self):
        epoll_poll = self._epoll.poll
        socks_lock = self._socks_lock
        registered_socks = self._registered_socks
        submit = self._get_executor().submit
        shutdown_event = DNSRelay._shutdown_event

        while not shutdown_event.is_set():

            try:
                l_socks = epoll_poll(timeout=1)
            except InterruptedError:
                continue
            for fd, event in l_socks:

                with socks_lock:
                    sock = registered_socks.get(fd)

                if (sock is None):
                    continue

                if (event & (select.EPOLLERR | select.EPOLLHUP)):
                    Log.error(f'[{fd}] epoll error/hup event')
                    continue

                try:
                    data, address = sock.recvfrom(2048)

                # can happen if poll returns, but packet invalid
                except OSError:
                    continue

                if (not DNSRelay._rate_limiter.allow(address[0])):
                    continue

                submit(self._parse_packet, data, address, sock)

    def _parse_packet(self, data, address, sock):
        client_query = ClientRequest(address, sock)
        try:
            local_domain = client_query.parse(data)
        except Exception as E:
            Log.error(f'[parser/client request] {E}')
            return

        Log.verbose(f'[{client_query.qname}] type={client_query.qtype} from {address}')

        DNSRelay._metrics.record_query(client_query.qtype)

        # if query flag is not set the packet will be assumed malformed and silently dropped
        if (local_domain or client_query.qr != DNS.QUERY): return

        # NOTE: guarding the entire dispatch/handling path (not just parsing) so a single malformed/edge-case
        # request cannot raise an uncaught exception and kill the single listener thread servicing every
        # registered interface. any failure here results in the individual request being dropped and logged.
        try:
            # check negative cache before any upstream work
            if (self._records_cache.is_negative(client_query.qname)):
                DNSRelay._metrics.record_negative_hit()
                Log.verbose(f'[{client_query.qname}] negative cache hit, returning nxdomain')
                client_query.generate_negative_response()
                self.send_to_client(client_query.send_data, client_query)
                return

            # A, NS, and AAAA records will have a cache pre-check before sending out
            if (client_query.qtype in [DNS.A, DNS.NS, DNS.AAAA]):

                Log.verbose(f'[{client_query.qname}] routed: cache pre-check')

                # no further action is required if cache contains matching record, otherwise request will be processed,
                # then added to queue for secure transmission to remote resolver. a genuine cache miss is exactly
                # the signal the top domains heuristic cares about (this domain is about to cause real upstream/WAN
                # traffic), so it is noted here rather than on every query attempt. NOTE: the top domain refresh
                # mechanism (DNSCache._auto_top_domains) calls _handle_query directly and never passes through here,
                # so this can't be self reinforced by the relay's own upkeep traffic. AAAA records are now cached
                # and counted towards top domains to reduce WAN chatter for both address families.
                if not self._cached_response(client_query):
                    self._records_cache_note_lookup(client_query.qname)
                    self._handle_query(client_query)

            # NOTE: a request reaching this point falls outside the scope of the relay and will be silently dropped
            else:
                Log.verbose(f'[{client_query.qname}] routed: unhandled type ({client_query.qtype}), dropped')

        except Exception as E:
            DNSRelay._metrics.record_error()
            Log.error(f'[handler/client request] {E}')

    def _cached_response(self, client_query):
        '''search cache for qname. if a record is found, a response will be generated and sent back to the client.'''

        cached_dom = self._records_cache_search(client_query.qname)
        if (cached_dom.records):

            Log.verbose(f'[{client_query.qname}] cache hit: {len(cached_dom.records)} records, '
                        f'TTL={cached_dom.ttl}')

            client_query.generate_cached_response(cached_dom)
            self.send_to_client(client_query.send_data, client_query)

            return True

        Log.verbose(f'[{client_query.qname}] cache miss')

    @classmethod
    # top_domain will now be set by caller so we don't have to track that within the query object.
    def _handle_query(cls, client_query, *, top_domain=False):
        new_dns_id = cls._get_unique_id()

        # extremely unlikely (would require the entire id space to be exhausted), but generate_dns_query would
        # otherwise blow up trying to pack None into the dns header. dropping the request is preferable to
        # taking down the listener thread.
        if (new_dns_id is None):
            Log.error(f'[request map] No available DNS ID for {client_query.qname}. Dropping request.')

            return

        client_query.generate_dns_query(new_dns_id)

        Log.verbose(f'Handling query for {client_query.qname} with ID {new_dns_id}.')

        with cls._id_lock:
            cls._request_map[new_dns_id] = (fast_time(), top_domain, client_query)

        TLSRelay.relay.add(client_query)

    @classmethod
    def _get_unique_id(cls):
        request_map = cls._request_map

        with cls._id_lock:
            for _ in range(100):
                dns_id = randint(70, 65534)
                if (dns_id not in request_map):
                    request_map[dns_id] = (fast_time(), False, None)
                    return dns_id

    @classmethod
    @tools.looper(THIRTY_SEC)
    def _clean_orphaned_ids(cls):
        now = fast_time()
        request_map = cls._request_map
        with cls._id_lock:
            orphaned = [dns_id for dns_id, (added_at, _, _) in list(request_map.items()) if added_at and now - added_at > RELAY_TIMEOUT]
            for dns_id in orphaned:
                request_map.pop(dns_id, None)
            if (orphaned):
                Log.verbose(f'[request map] cleaned {len(orphaned)} orphaned entries')

    @relay_queue(Log, name='DNSRelay')
    def responder(self, received_data):
        # dns id is the first 2 bytes in the dns header
        dns_id = short_unpackf(received_data)[0]

        entry = self._request_map_pop(dns_id, None)
        if (entry is None):
            Log.verbose(f'[responder] orphan response for DNS ID {dns_id}')
            return

        added_at, top_domain, client_query = entry

        Log.verbose(f'[responder] response for {client_query.qname} (ID {dns_id}) '
                    f'from {client_query.address}')

        try:
            server_response, cache_data, rcode = ttl_rewrite(received_data, client_query.dns_id)
        except Exception as E:
            Log.error(f'[parser/server response] {E}')
        else:
            # negative-cache only true NXDOMAIN (rc==3). SERVFAIL (rc==2) is transient / a DNSSEC
            # validation failure -- forward the real upstream response, never cache it as NXDOMAIN.
            if (rcode == 3 and not top_domain):
                self._records_cache.add_negative(client_query.qname)
            if (not top_domain):
                Log.verbose(f'[responder] forwarding {len(server_response)} bytes to '
                            f'{client_query.address}')
                self.send_to_client(server_response, client_query)

            if (cache_data):
                Log.verbose(f'[responder] caching {len(cache_data.records)} records for '
                            f'{client_query.qname}')
                self._records_cache_add(client_query.qname, cache_data)

    @staticmethod
    def send_to_client(server_response, client_query):
        try:
            client_query.sendto(server_response, client_query.address)
        except OSError:
            Log.error(f'[send] Failed response to {client_query.address}.')

    @staticmethod
    def _listener_sock(listen_ip):
        l_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            l_sock.bind((f'{listen_ip}', PROTO.DNS))
        except OSError:
            Log.error(f'[{listen_ip}] Failed to bind address!')
            hard_out()

        l_sock.setblocking(False)
        l_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        return l_sock


class DNSCache(dict):
    '''subclass of dict to provide a custom data structure for dealing with the local caching of dns records.

    containers handled by class:
        general dict - standard cache storage
        private Counter - tracking actual upstream lookups caused by each domain

    initialization is the same as a dict, with the addition of two required method calls for callback references
    to the dns server.

        packet (*reference to packet class*)
        request_handler (*reference to dns server request handler function*)

    if the above callbacks are not set the top domains caching system will NOT actively update records, though the counts
    will still be accurate/usable.

    top domains ranking:
        a domain's score is only incremented when it actually causes an upstream lookup (see note_lookup/callers),
        not on every client query, so ranking reflects real WAN chatter caused rather than raw popularity. every
        refresh cycle the score is decayed by a self adjusting rate: if the qualifying set churns a lot cycle to
        cycle (a sign decay is currently too aggressive relative to the real signal), the rate automatically slows
        down to stabilize; if the set is stable, the rate speeds back up so the system stays responsive to genuine
        future changes instead of clinging to stale history forever. a domain must also retain at least
        TOP_DOMAIN_MIN_SHARE of the current leading domain's score to qualify, which self scales with however much
        traffic this particular network/deployment actually generates instead of relying on a fixed absolute count.
        both bounds live in dns_tls_constants.py as documented safety rails, not tuned operating points.
    '''

    __slots__ = (
        '_dns_packet', '_request_handler', '_persist',

        '_dom_counter', '_burst_counter', '_cnter_lock',
        '_prev_top_set', '_burst_decay_rate',
        '_expiry_heap', '_heap_lock',

        '_negative_cache', '_negative_lock',
    )

    def __init__(self, *, dns_packet=None, request_handler=None, persist=True):
        self._dns_packet = dns_packet
        self._request_handler = request_handler

        # "paranoid mode" support (run_relay.py -m): when disabled, the top domains cache never touches disk at
        # all in either direction, so no plaintext record of locally observed query activity can be recovered
        # from this device (eg. on physical access/seizure) at the cost of the permanently-cached top domains
        # not surviving a restart.
        self._persist = persist

        self._dom_counter = Counter()
        self._burst_counter = Counter()
        self._cnter_lock  = threading.Lock()
        self._expiry_heap = []
        self._heap_lock   = threading.Lock()

        # adaptive burst decay state -- starts at the most conservative/stable rate until there has been at least
        # one prior cycle to actually measure churn against.
        self._prev_top_set = frozenset()
        self._burst_decay_rate = BURST_ADAPT_MAX

        # negative cache: dict of qname -> expiry timestamp
        self._negative_cache = {}
        self._negative_lock = threading.Lock()

        self._load_top_domains()

        t = threading.Thread(target=self._auto_clear_cache)
        t.daemon = True
        t.start()

        t = threading.Thread(target=self._auto_clear_negative)
        t.daemon = True
        t.start()

        if (dns_packet and request_handler):
            t = threading.Thread(target=self._auto_top_domains)
            t.daemon = True
            t.start()

    # searching key directly will return calculated ttl and associated records
    def __getitem__(self, key):
        # filtering root lookups from checking cache
        if (not key):
            return DNS_CACHE(NOT_VALID, None)

        record = dict.__getitem__(self, key)
        # not present
        if (record == NOT_VALID):
            return DNS_CACHE(NOT_VALID, None)

        calcd_ttl = record.expire - int(fast_time())
        if (calcd_ttl > DEFAULT_TTL):
            return DNS_CACHE(DEFAULT_TTL, record.records)

        elif (calcd_ttl > 0):
            return DNS_CACHE(calcd_ttl, record.records)
        # expired
        else:
            return DNS_CACHE(NOT_VALID, None)

    # if missing will return an expired result
    def __missing__(self, key):
        return NOT_VALID

    def add(self, qname, data_to_cache):
        '''add query to cache after calculating expiration time.'''
        with self._heap_lock:
            self[qname] = data_to_cache
            heapq.heappush(self._expiry_heap, (data_to_cache.expire, qname))

        Log.verbose(f'[{qname}:{data_to_cache.ttl}] Added to standard cache. ')

    def search(self, qname):
        '''if client requested domain is present in cache, will return namedtuple of time left on ttl
        and the dns records, otherwise will return None.'''

        return self[qname]

    def add_negative(self, qname, ttl=NEGATIVE_CACHE_TTL):
        '''cache that a domain returned nxdomain/servfail so repeat lookups don't hit upstream.'''
        if (self._is_filtered(qname)):
            return

        with self._negative_lock:
            self._negative_cache[qname] = fast_time() + ttl

        Log.verbose(f'[negative cache] added {qname} (ttl={ttl}s)')

    def is_negative(self, qname):
        '''check if a domain is in the negative cache and still valid. caller should respond with the
        appropriate nxdomain/servfail response immediately.'''
        with self._negative_lock:
            expire = self._negative_cache.get(qname)
            if (expire is not None):
                if (fast_time() < expire):
                    Log.verbose(f'[negative cache] hit {qname}')
                    return True

                del self._negative_cache[qname]

            return False

    def note_lookup(self, domain):
        '''record that a domain caused (or is about to cause) an actual upstream lookup, for top domains ranking
        purposes. callers should only invoke this for genuine, client triggered lookups -- see call sites.
        domains matching the static noise filter (dns_tls_constants.DOMAIN_FILTER) or made up of a rotating/
        anonymous numeric label (eg. ntp pool style "0.pool.ntp.org") are excluded.'''
        if (not domain or self._is_filtered(domain)):
            return

        with self._cnter_lock:
            self._dom_counter[domain] += 1
            self._burst_counter[domain] += 1

    @staticmethod
    def _is_filtered(domain):
        '''True if domain should never be considered for the top domains cache. filter terms are matched against
        whether a dot separated label of the domain *starts with* the term (not a raw substring-anywhere check
        against the full domain string) so eg. 'api' matches "api.example.com"/"api2.example.com" but not an
        unrelated domain that merely happens to contain "api" mid word. purely numeric labels are always excluded
        since they are almost always rotating/anonymous shard or pool identifiers rather than a meaningful,
        individually cache worthy hostname.'''
        labels = domain.split('.')

        if any(label.isdigit() for label in labels):
            return True

        return any(label.startswith(fltr) for label in labels for fltr in DOMAIN_FILTER)

    @tools.looper(THREE_MIN)
    # automated process to flush the cache if expire time has been reached.
    def _auto_clear_cache(self):
        now = fast_time()
        heap = self._expiry_heap
        with self._heap_lock:
            while heap and heap[0][0] <= now:
                expire, qname = heapq.heappop(heap)
                record = self.get(qname)
                if record and record.expire == expire:
                    del self[qname]

    @tools.looper(NEGATIVE_CACHE_CLEAN_INTERVAL)
    def _auto_clear_negative(self):
        now = fast_time()
        with self._negative_lock:
            expired = [qname for qname, expire in self._negative_cache.items() if expire < now]
            for qname in expired:
                del self._negative_cache[qname]

            if (expired):
                Log.verbose(f'[negative cache] cleaned {len(expired)} expired entries')

    @tools.looper(THREE_MIN)
    # automated process to keep the top queried domains permanently in cache. it will use the current caches packet
    # to generate a new packet and add to the standard tls queue. the receiving end will know how to handle this by
    # setting top_domain=True (see DNSRelay._handle_query/.responder) so it does not respond to the (nonexistent)
    # client nor reinforce the domain's own ranking.
    def _auto_top_domains(self):
        top_domains = self._rank_top_domains()

        request_handler, dns_packet = self._request_handler, self._dns_packet
        for domain in top_domains:
            request_handler(dns_packet(domain), top_domain=True)

            # rate limited to make it less aggressive
            fast_sleep(.1)

        if (self._persist):
            tools.write_cache(top_domains)

    def _rank_top_domains(self):
        '''multi-timeframe scoring: decays the burst counter fast (responsive to recent spikes) and the
        stability counter slowly (recognizes long-term patterns). the combined score = burst + stability
        captures both. the burst decay rate is self-tuned based on churn, while stability has a fixed slow
        decay. returns a plain {domain: rank} dict ordered best to worst, ready to persist/relay.'''
        with self._cnter_lock:
            for domain in list(self._burst_counter):
                decayed = self._burst_counter[domain] * self._burst_decay_rate
                if (decayed < 0.5):
                    del self._burst_counter[domain]
                else:
                    self._burst_counter[domain] = decayed

            for domain in list(self._dom_counter):
                decayed = self._dom_counter[domain] * STABILITY_DECAY_RATE
                if (decayed < 1):
                    del self._dom_counter[domain]
                else:
                    self._dom_counter[domain] = decayed

            combined = {
                domain: self._burst_counter.get(domain, 0) + self._dom_counter.get(domain, 0)
                for domain in set(self._burst_counter) | set(self._dom_counter)
            }
            ranked = Counter(combined).most_common(TOP_DOMAIN_COUNT)

            # relative/self-scaling qualification bar -- a domain must still be meaningfully active compared to the
            # current leader, regardless of whether this network generates tens or tens of thousands of lookups per
            # cycle, rather than needing to clear some fixed absolute count.
            peak = ranked[0][1] if ranked else 0
            qualifying = [domain for domain, count in ranked if count >= peak * TOP_DOMAIN_MIN_SHARE]

            self._adapt_burst_decay(frozenset(qualifying))

        return {domain: rank for rank, domain in enumerate(qualifying, 1)}

    def _adapt_burst_decay(self, new_top_set):
        '''self tuning feedback loop for the burst counter's decay rate. uses rank-weighted churn:
        high-rank changes (top of the list) penalized more than tail shuffles, so the rate won't
        over-react to noise in the long tail. always bounded to [BURST_ADAPT_MIN, BURST_ADAPT_MAX]
        and smoothed halfway to prevent whipsaw.'''
        if (self._prev_top_set):
            top5_prev = {d for i, d in enumerate(sorted(self._prev_top_set)) if i < 5}
            top5_new  = {d for i, d in enumerate(sorted(new_top_set)) if i < 5}

            union_all = len(new_top_set | self._prev_top_set) or 1
            inter_all = len(new_top_set & self._prev_top_set)
            union_top5 = len(top5_new | top5_prev) or 1
            inter_top5 = len(top5_new & top5_prev)

            churn_all  = 1 - (inter_all / union_all)
            churn_top5 = 1 - (inter_top5 / union_top5)

            churn = 0.3 * churn_all + 0.7 * churn_top5

            target = BURST_ADAPT_MIN + churn * (BURST_ADAPT_MAX - BURST_ADAPT_MIN)
            self._burst_decay_rate = (self._burst_decay_rate + target) / 2

            promoted, demoted = new_top_set - self._prev_top_set, self._prev_top_set - new_top_set
            if (promoted or demoted):
                Log.verbose(f'[top domains] promoted={sorted(promoted)} demoted={sorted(demoted)}')

            Log.verbose(f'[top domains] churn={churn:.2f} rate={self._burst_decay_rate:.3f}')

        self._prev_top_set = new_top_set

    # loads top domains from file for persistence between restarts/shutdowns. skipped entirely in paranoid/
    # memory-only mode so nothing is ever read from (or, per _auto_top_domains, written to) disk.
    def _load_top_domains(self):
        if (not self._persist):
            return

        dns_cache = tools.load_cache('top_domains')

        loaded = list(dns_cache['top_domains'])
        self._dom_counter = Counter({
            domain: count for count, domain in enumerate(reversed(loaded))
        })
        # seed burst counter from loaded ranks so newly loaded domains don't start at zero
        self._burst_counter = Counter({
            domain: max(3 - rank, 1) for rank, domain in enumerate(loaded, 1)
        })
