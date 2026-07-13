#!/usr/bin/env python3

import threading
import socket
import select

from random import randint
from collections import Counter

import basic_tools as tools

from dns_tls_constants import *

from basic_tools import Log
from advanced_tools import relay_queue

from dns_tls_protocols import TLSRelay, Reachability
from dns_tls_packets import ClientRequest, ttl_rewrite

__all__ = (
    'DNSRelay'
)


class DNSRelay:
    protocol = PROTO.DNS_TLS

    # flag used to check status of relay. if one remote server is up, tls_up=True. both remote servers have to be down
    # for tls_up=False.
    tls_up = False
    keepalive_interval = 0

    dns_servers = DNS_SERVERS(
        {'ip': None, PROTO.DNS_TLS: False},
        {'ip': None, PROTO.DNS_TLS: False}
    )

    _epoll = select.epoll()
    _registered_socks = {}
    _request_map = {}
    _id_lock = threading.Lock()

    def __init__(self):
        threading.Thread(target=self.responder).start()

        # assigning object methods to prevent lookup
        self._request_map_pop = self._request_map.pop

        self._records_cache_add = self._records_cache.add
        self._records_cache_search = self._records_cache.search
        self._records_cache_note_lookup = self._records_cache.note_lookup

    @classmethod
    def run(cls, listening_addresses, keepalive_interval, persist_top_domains=True):
        Log.system('Initializing primary service...')

        cls.keepalive_interval = keepalive_interval

        # running main epoll/ socket loop. threaded so proxy and server can run side by side
        # NOTE: threading.Thread(target=service_loop._listener).start() starting a registration thread for all available
        # interfaces. once registered the threads will exit.
        for ip_addr in listening_addresses:
            threading.Thread(target=cls._register, args=(f'{ip_addr}',)).start()

        Reachability.run(cls)
        TLSRelay.run(cls)

        # initializing dns cache/ sending in reference to needed methods for top domains
        cls._records_cache = DNSCache(
            dns_packet=ClientRequest.generate_local_query,
            request_handler=cls._handle_query,
            persist=persist_top_domains
        )

        threading.Thread(target=cls()._listener).start()

    @classmethod
    def _register(cls, listener_ip):
        '''will register interface with listener. requires subclass property for listener_sock returning valid socket
         object. once registration is complete the thread will exit.'''

        Log.system(f'[{listener_ip}] Started registration.')

        l_sock = cls._listener_sock(listener_ip)
        cls._registered_socks[l_sock.fileno()] = L_SOCK(listener_ip, l_sock, l_sock.sendto, l_sock.recvfrom)

        cls._epoll.register(l_sock.fileno(), select.EPOLLIN)

        Log.system(f'[{listener_ip}][{l_sock.fileno()}] Listener registered.')

    def _listener(self):
        epoll_poll = self._epoll.poll
        registered_socks_get = self._registered_socks.get
        parse_packet = self._parse_packet

        for _ in RUN_FOREVER():

            l_socks = epoll_poll()
            for fd, _ in l_socks:

                sock = registered_socks_get(fd)

                try:
                    data, address = sock.recvfrom(2048)

                # can happen if poll returns, but packet invalid
                except OSError:
                    continue

                parse_packet(data, address, sock)

    def _parse_packet(self, data, address, sock):
        client_query = ClientRequest(address, sock)
        try:
            local_domain = client_query.parse(data)
        except Exception as E:
            Log.error(f'[parser/client request] {E}')
            return

        # if query flag is not set the packet will be assumed malformed and silently dropped
        if (local_domain or client_query.qr != DNS.QUERY): return

        # NOTE: guarding the entire dispatch/handling path (not just parsing) so a single malformed/edge-case
        # request cannot raise an uncaught exception and kill the single listener thread servicing every
        # registered interface. any failure here results in the individual request being dropped and logged.
        try:
            # A and NS records will have a cache pre-check before sending out
            if (client_query.qtype in [DNS.A, DNS.NS]):

                # no further action is required if cache contains matching record, otherwise request will be processed,
                # then added to queue for secure transmission to remote resolver. a genuine cache miss is exactly
                # the signal the top domains heuristic cares about (this domain is about to cause real upstream/WAN
                # traffic), so it is noted here rather than on every query attempt. NOTE: the top domain refresh
                # mechanism (DNSCache._auto_top_domains) calls _handle_query directly and never passes through here,
                # so this can't be self reinforced by the relay's own upkeep traffic.
                if not self._cached_response(client_query):
                    self._records_cache_note_lookup(client_query.qname)
                    self._handle_query(client_query)

            # AAAA records does not get cached so the check will be skipped. NOTE: intentionally not counted
            # towards top domains -- the permanent cache refresh mechanism only ever re-queries the A record for a
            # domain, so ranking one based on AAAA-only traffic wouldn't actually reduce any real upstream chatter.
            elif (client_query.qtype in [DNS.AAAA]):
                self._handle_query(client_query)

            # NOTE: a request reaching this point falls outside the scope of the relay and will be silently dropped

        except Exception as E:
            Log.error(f'[handler/client request] {E}')

    def _cached_response(self, client_query):
        '''search cache for qname. if a record is found, a response will be generated and sent back to the client.'''

        cached_dom = self._records_cache_search(client_query.qname)
        if (cached_dom.records):

            client_query.generate_cached_response(cached_dom)
            self.send_to_client(client_query.send_data, client_query)

            return True

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

        cls._request_map[new_dns_id] = (top_domain, client_query)

        TLSRelay.relay.add(client_query)

    @classmethod
    def _get_unique_id(cls):
        request_map = cls._request_map

        with cls._id_lock:
            # NOTE: maybe tune this number. under high load collisions could occur and we don't want it to waste time
            # because other requests must wait for this process to complete since we are now using a queue system for
            # while waiting for a decision instead of individual threads.
            for _ in range(100):

                dns_id = randint(70, 32000)
                if (dns_id not in request_map):

                    request_map[dns_id] = 1

                    return dns_id

    @relay_queue(Log, name='DNSRelay')
    def responder(self, received_data):
        # dns id is the first 2 bytes in the dns header
        dns_id = short_unpackf(received_data)[0]

        top_domain, client_query = self._request_map_pop(dns_id, (None, None))
        if (not client_query):
            return

        try:
            server_response, cache_data = ttl_rewrite(received_data, client_query.dns_id)
        except Exception as E:
            Log.error(f'[parser/server response] {E}')
        else:
            if (not top_domain):
                self.send_to_client(server_response, client_query)

            if (cache_data):
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

        '_dom_counter', '_cnter_lock',
        '_prev_top_set', '_decay_rate',
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
        self._cnter_lock  = threading.Lock()

        # adaptive decay state -- starts at the most conservative/stable rate until there has been at least one
        # prior cycle to actually measure churn against.
        self._prev_top_set = frozenset()
        self._decay_rate = TOP_DOMAIN_DECAY_MAX

        self._load_top_domains()
        threading.Thread(target=self._auto_clear_cache).start()
        if (dns_packet and request_handler):
            threading.Thread(target=self._auto_top_domains).start()

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
        self[qname] = data_to_cache

        Log.verbose(f'[{qname}:{data_to_cache.ttl}] Added to standard cache. ')

    def search(self, qname):
        '''if client requested domain is present in cache, will return namedtuple of time left on ttl
        and the dns records, otherwise will return None.'''

        return self[qname]

    def note_lookup(self, domain):
        '''record that a domain caused (or is about to cause) an actual upstream lookup, for top domains ranking
        purposes. callers should only invoke this for genuine, client triggered lookups -- see call sites.
        domains matching the static noise filter (dns_tls_constants.DOMAIN_FILTER) or made up of a rotating/
        anonymous numeric label (eg. ntp pool style "0.pool.ntp.org") are excluded.'''
        if (not domain or self._is_filtered(domain)):
            return

        with self._cnter_lock:
            self._dom_counter[domain] += 1

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
        expired = [dom for dom, record in self.items() if now > record.expire]

        for domain in expired:
            del self[domain]

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
        '''decays existing scores using the current self tuning rate (pruning anything that falls below one
        whole lookup equivalent, which also keeps the counter's memory use bounded over long uptimes), ranks the
        surviving candidates, applies the relative qualification threshold, then adapts the decay rate for next
        cycle based on how much the qualifying set churned versus last cycle. returns a plain {domain: rank}
        dict ordered best to worst, ready to persist/relay.'''
        with self._cnter_lock:
            for domain in list(self._dom_counter):
                decayed = self._dom_counter[domain] * self._decay_rate

                if (decayed < 1):
                    del self._dom_counter[domain]
                else:
                    self._dom_counter[domain] = decayed

            ranked = self._dom_counter.most_common(TOP_DOMAIN_COUNT)

        # relative/self-scaling qualification bar -- a domain must still be meaningfully active compared to the
        # current leader, regardless of whether this network generates tens or tens of thousands of lookups per
        # cycle, rather than needing to clear some fixed absolute count.
        peak = ranked[0][1] if ranked else 0
        qualifying = [domain for domain, count in ranked if count >= peak * TOP_DOMAIN_MIN_SHARE]

        self._adapt_decay_rate(frozenset(qualifying))

        return {domain: rank for rank, domain in enumerate(qualifying, 1)}

    def _adapt_decay_rate(self, new_top_set):
        '''self tuning feedback loop: if the qualifying set is churning heavily cycle to cycle, that suggests the
        current decay rate is too aggressive relative to the real signal (letting noise dominate), so slow down
        (retain more history). if the set is stable, speed back up so the system stays maximally responsive to
        genuine future changes instead of clinging to stale history. always bounded to [TOP_DOMAIN_DECAY_MIN,
        TOP_DOMAIN_DECAY_MAX] so it can never degenerate to instant amnesia or infinite memory, and the adjustment
        itself is smoothed (moved halfway to the new target) so the rate doesn't whipsaw cycle to cycle.'''
        if (self._prev_top_set):
            union_size = len(new_top_set | self._prev_top_set) or 1
            stable = len(new_top_set & self._prev_top_set)
            churn = 1 - (stable / union_size)

            target = TOP_DOMAIN_DECAY_MIN + churn * (TOP_DOMAIN_DECAY_MAX - TOP_DOMAIN_DECAY_MIN)
            self._decay_rate = (self._decay_rate + target) / 2

            promoted, demoted = new_top_set - self._prev_top_set, self._prev_top_set - new_top_set
            if (promoted or demoted):
                Log.verbose(f'[top domains] promoted={sorted(promoted)} demoted={sorted(demoted)}')

            Log.verbose(f'[top domains] churn={churn:.2f} decay_rate={self._decay_rate:.3f}')

        self._prev_top_set = new_top_set

    # loads top domains from file for persistence between restarts/shutdowns. skipped entirely in paranoid/
    # memory-only mode so nothing is ever read from (or, per _auto_top_domains, written to) disk.
    def _load_top_domains(self):
        if (not self._persist):
            return

        dns_cache = tools.load_cache('top_domains')

        self._dom_counter = Counter({
            domain: count for count, domain in enumerate(reversed(list(dns_cache['top_domains'])))
        })
