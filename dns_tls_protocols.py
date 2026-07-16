#!/usr/bin/env python3

import threading
import ssl

from random import shuffle
from socket import socket, AF_INET, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY

from dns_tls_constants import *

from basic_tools import Log, looper
from advanced_tools import relay_queue, Initialize

from dns_tls_packets import ClientRequest

ATTEMPTS = (0, 1)

ALPHA = 0.9  # EMA smoothing factor for latency tracking


class ProviderConnection:
    '''holds the state for a single upstream provider connection. each active provider
    gets its own socket, latency tracker, and failure counters so the relay can pool
    connections and select the best performer intelligently.'''

    __slots__ = (
        'server_ip', 'sock', 'tls_version',
        'send_cnt', 'last_rcvd', 'last_send_time',
        'avg_latency', 'success_count', 'fail_count',
    )

    def __init__(self, server_ip, sock, tls_version):
        self.server_ip = server_ip
        self.sock = sock
        self.tls_version = tls_version
        self.send_cnt = 0
        self.last_rcvd = 0
        self.last_send_time = 0
        self.avg_latency = 0.0
        self.success_count = 0
        self.fail_count = 0

    @property
    def is_active(self):
        return self.sock is not None

    def record_latency(self, latency):
        '''update exponential moving average of response latency.'''
        if (self.avg_latency == 0):
            self.avg_latency = latency
        else:
            self.avg_latency = ALPHA * self.avg_latency + (1 - ALPHA) * latency


def _build_tls_context():
    '''creates a TLS client context used to validate the remote DoT resolver's certificate.

    uses the system/OpenSSL default trust store (honoring SSL_CERT_FILE/SSL_CERT_DIR if set) rather than a
    hardcoded path so this works across distros/containers that don't keep CA certs at the Debian/Ubuntu
    specific location of /etc/ssl/certs/ca-certificates.crt.
    '''
    tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    tls_context.verify_mode = ssl.CERT_REQUIRED
    tls_context.load_default_certs()

    # explicit floor rather than relying on whatever PROTOCOL_TLS_CLIENT/OpenSSL currently defaults to, so a
    # future change in defaults (or a downgrade attempt) can't silently negotiate a weaker, legacy protocol
    # version for DNS traffic that is supposed to be private.
    tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
    tls_context.set_ciphers(
        'ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS:!SHA1:!CBC'
    )

    return tls_context


class ProtoRelay:
    '''parent class for udp and tls relays providing standard built in methods to start, check status, or add jobs to
     the work queue. '''
    _protocol  = PROTO.NOT_SET

    __slots__ = (
        'DNSRelay', '_relay_conn', '_responder_add',

        '_send_cnt', '_last_rcvd',
    )

    def __new__(cls, *args, **kwargs):
        if (cls is ProtoRelay):
            raise TypeError('ProtoRelay can only be used via inheritance.')

        return object.__new__(cls)

    def __init__(self, DNSRelay):
        '''general constructor. can only be reached through subclass.'''
        self.DNSRelay = DNSRelay

        self._relay_conn = RELAY_CONN(None, None, None, None, None)

        self._send_cnt  = 0
        self._last_rcvd = 0

    @classmethod
    def run(cls, DNSRelay):
        '''starts the protocol relay. DNSServer object is the class handling client side requests which we can call back
        to and fallback is a secondary relay that can get forwarded a request post failure. initialize will be called
        to run any subclass specific processing then query handler will run indefinitely.'''
        self = cls(DNSRelay)
        cls._instance = self

        t = threading.Thread(target=self._fail_detection)
        t.daemon = True
        t.start()

        t = threading.Thread(target=self.relay)
        t.daemon = True
        t.start()

    @classmethod
    def shutdown(cls):
        '''gracefully close all provider connections and release resources. intended to be
        called once from DNSRelay.shutdown() during process termination.'''
        raise NotImplementedError('shutdown must be implemented in the subclass.')

    def relay(self):
        '''main relay process for handling the relay queue. will block and run forever.'''

        raise NotImplementedError('relay must be implemented in the subclass.')

    def _send_query(self, client_query):
        for attempt in ATTEMPTS:
            Log.verbose(f'[send] attempt {attempt} for {client_query.qname} '
                        f'({len(client_query.send_data)} bytes)')

            try:
                self._relay_conn.send(client_query.send_data)
            except OSError:
                Log.verbose(f'[send] attempt {attempt} failed, reconnecting...')
                if not self._register_new_socket(): return

                threading.Thread(target=self._recv_handler).start()

            else:
                break

        # incrementing fail detection count
        self._send_cnt += 1

        # general log for queries being sent which also identifies a new tls connection
        Log.console(
            f'[{self._relay_conn.remote_ip}/{self._relay_conn.version}][{attempt}] Sent {client_query.qname}'
        )

    def _recv_handler(self):
        '''called in a thread after creating new socket to handle all responses from remote server.'''

        raise NotImplementedError('_recv_handler method must be overridden in subclass.')

    def _register_new_socket(self):
        '''logic to create socket object used for external dns queries.'''

        raise NotImplementedError('_register_new_socket method must be overridden in subclass.')

    @looper(FIVE_SEC)
    def _fail_detection(self):
        if (fast_time() - self._last_rcvd >= FIVE_SEC and self._send_cnt >= HEARTBEAT_FAIL_LIMIT):
            self.mark_server_down()

    # processes that were unable to connect/ create a socket will send in the remote server ip that was attempted. if a
    # remote server isn't specified the active relay socket connection's remote ip will be used. we don't know which
    # ip goes to which server position, so we have to iterate over the pair and match. this works out better because
    # it allows us to not have to track position/server ips, especially when users can change them while running (only
    # applicable to dnxfirewall, but I want the codebase to emulate one another.)
    def mark_server_down(self, *, remote_server=None):
        if (not remote_server):
            remote_server = self._relay_conn.remote_ip

        # more likely case is primary server going down so will use as baseline condition
        primary = self.DNSRelay.dns_servers.primary

        # if servers could change during runtime, this has a slight race condition potential, but it shouldn't matter
        # because when changing a server it would be initially set to down (essentially a no-op)
        server = primary if primary['ip'] == remote_server else self.DNSRelay.dns_servers.secondary
        Log.verbose(f'[{remote_server}] marking server DOWN')
        server[PROTO.DNS_TLS] = False

        try:
            self._relay_conn.sock.close()
        except OSError:
            Log.error(f'[{self._relay_conn.remote_ip}] Failed to close socket while marking server down.')


class TLSRelay(ProtoRelay):
    _protocol   = PROTO.DNS_TLS
    _dns_packet = ClientRequest.generate_local_query

    __slots__ = (
        '_tls_context', '_providers', '_providers_lock',
        '_keepalive_event',
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self._tls_context = _build_tls_context()

        self._providers = []
        self._providers_lock = threading.Lock()

        self._keepalive_event = threading.Event()

        if (self.DNSRelay.keepalive_interval):
            t = threading.Thread(target=self._keepalive_run)
            t.daemon = True
            t.start()

    @classmethod
    def shutdown(cls):
        Log.system('TLSRelay shutting down provider connections...')

        if not hasattr(cls, '_instance'):
            return
        self = cls._instance

        with self._providers_lock:
            for provider in list(self._providers):
                try:
                    if provider.sock:
                        provider.sock.close()
                except OSError:
                    pass
            self._providers.clear()

        Log.system('TLSRelay shutdown complete.')

    def _best_provider(self):
        '''return the active provider with the lowest average latency,
        falling back to any active provider if none have been measured yet.'''
        with self._providers_lock:
            active = [p for p in self._providers if p.is_active]
            if (not active):
                return None

            best = min(active, key=lambda p: p.avg_latency if p.avg_latency > 0 else float('inf'))
            return best

    def _establish_connections(self):
        '''connect to all available providers and start a recv handler for each.
        returns True if at least one connection was established.'''
        tls_servers = list(self.DNSRelay.dns_servers)
        shuffle(tls_servers)

        Log.verbose(f'[connection] preference order: {[s["ip"] for s in tls_servers]}')

        connected = False
        for tls_server in tls_servers:
            ip = tls_server['ip']

            with self._providers_lock:
                already = any(p.server_ip == ip and p.is_active for p in self._providers)
            if (already):
                continue

            if (not tls_server[self._protocol]):
                Log.verbose(f'[connection] {ip} is down, skipping')
                continue

            provider = self._tls_connect(ip)
            if (provider):
                with self._providers_lock:
                    self._providers.append(provider)
                t = threading.Thread(target=self._recv_handler, args=(provider,))
                t.daemon = True
                t.start()
                connected = True
                Log.system(f'[{ip}/{self._protocol.name}] Connected (pool)')
            else:
                self.mark_server_down(remote_server=ip)

        if (not connected):
            self.DNSRelay.tls_up = False
            Log.console(f'[{self._protocol}] No DNS servers available.')

        self.DNSRelay.tls_up = connected
        return connected

    def _reconnect_provider(self, provider):
        '''close and reconnect a single provider. used when a send fails on
        an otherwise-active connection.'''
        try:
            provider.sock.close()
        except OSError:
            pass

        provider.sock = None
        Log.verbose(f'[{provider.server_ip}] Reconnecting...')

        new_provider = self._tls_connect(provider.server_ip)
        if (new_provider):
            with self._providers_lock:
                self._providers.remove(provider)
                self._providers.append(new_provider)
            t = threading.Thread(target=self._recv_handler, args=(new_provider,))
            t.daemon = True
            t.start()
            return True

        with self._providers_lock:
            if provider in self._providers:
                self._providers.remove(provider)
        self.mark_server_down(remote_server=provider.server_ip)
        return False

    # overrides ProtoRelay._register_new_socket to work with the pool
    def _register_new_socket(self, client_query=None):
        with self._providers_lock:
            active = [p for p in self._providers if p.is_active]
        if (active):
            return True

        return self._establish_connections()

    @relay_queue(Log, name='TLSRelay')
    def relay(self, client_query):
        self._send_query(client_query)

    def _send_query(self, client_query):
        '''send a query to upstream providers. for top-domain refresh/keepalive
        (single-answer-needed), uses only the best provider. for client queries,
        fans out to all active providers and takes the first response.'''
        with self._providers_lock:
            active = [p for p in self._providers if p.is_active]

        if (not active):
            if (not self._register_new_socket()):
                return
            with self._providers_lock:
                active = [p for p in self._providers if p.is_active]

        if (not active):
            return

        # fan-out: send to all active providers for client queries,
        # but only the best one for internal refresh/keepalive traffic
        targets = active if not getattr(client_query, 'top_domain', False) else [self._best_provider() or active[0]]

        for provider in targets:
            try:
                provider.sock.send(client_query.send_data)
                provider.send_cnt += 1
                provider.last_send_time = fast_time()
                Log.console(
                    f'[{provider.server_ip}/{provider.tls_version}] Sent {client_query.qname}'
                )
            except (OSError, AttributeError):
                Log.verbose(f'[{provider.server_ip}] send failed, attempting reconnect...')
                self._reconnect_provider(provider)

    def _recv_handler(self, provider):
        '''per-connection receive handler. reads responses from a single provider's
        socket, tracks the response latency for that provider, and feeds completed
        dns responses into the relay's responder queue.'''
        Log.debug(f'[{provider.server_ip}/{self._protocol.name}] Response handler started.')

        conn_recv = provider.sock.recv

        recv_buffer = []
        recv_buff_append = recv_buffer.append
        recv_buff_clear  = recv_buffer.clear

        responder_add = self.DNSRelay.responder.add

        for _ in RUN_FOREVER():
            try:
                data_from_server = conn_recv(2048)

            except OSError:
                break

            else:
                if (not data_from_server):
                    break

                now = fast_time()
                provider.last_rcvd = now
                provider.send_cnt = 0

                if (provider.last_send_time):
                    provider.record_latency(now - provider.last_send_time)

                self._keepalive_event.set()

                recv_buff_append(data_from_server)
                while recv_buffer:
                    current_data = byte_join(recv_buffer)

                    # need at least 2 bytes for the DNS-over-TLS length prefix
                    if (len(current_data) < 2): break

                    data_len = short_unpackf(current_data)[0]
                    total_len = 2 + data_len

                    # minimum valid DNS message is 12 bytes (header only); reject
                    # malformed frames that would desync the parser or waste memory.
                    if (data_len < 12):
                        recv_buff_clear()
                        Log.error(f'[{provider.server_ip}] invalid frame length ({data_len}), discarding')
                        break

                    if (len(current_data) < total_len): break

                    recv_buff_clear()
                    frame = current_data[2:total_len]

                    if (len(current_data) > total_len):
                        recv_buff_append(current_data[total_len:])

                    if (frame[0] != DNS.KEEPALIVE):
                        responder_add(frame)

        provider.sock.close()
        provider.sock = None

        Log.verbose(f'[{provider.server_ip}/{self._protocol.name}] Connection closed.')

    def _tls_connect(self, tls_server):
        '''connect to a single DoT resolver and return a ProviderConnection,
        or None on failure.'''
        Log.verbose(f'[{tls_server}/{self._protocol.name}] Opening secure socket.')

        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)

        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)

        dot_sock = self._tls_context.wrap_socket(sock, server_hostname=tls_server)
        try:
            dot_sock.connect((tls_server, PROTO.DNS_TLS))
        except OSError as ose:
            Log.error(f'[{tls_server}/{self._protocol.name}] Failed to connect. {ose}')

        except Exception as E:
            Log.error(f'[{tls_server}/{self._protocol.name}] While attempting to connect: {E}')

        else:
            dot_sock.settimeout(RELAY_TIMEOUT)

            tls_version = dot_sock.version()
            tls_cipher = dot_sock.cipher()
            Log.verbose(f'[{tls_server}] TLS {tls_version} cipher={tls_cipher[0]}')

            return ProviderConnection(tls_server, dot_sock, tls_version)

        return None

    def mark_server_down(self, *, remote_server=None):
        '''mark a provider as down in the server status dict (no-op for closing the
        socket since the pool manages that per-connection).'''
        if (not remote_server):
            return

        primary = self.DNSRelay.dns_servers.primary
        server = primary if primary['ip'] == remote_server else self.DNSRelay.dns_servers.secondary
        Log.verbose(f'[{remote_server}] marking server DOWN')
        server[PROTO.DNS_TLS] = False

    def _keepalive_run(self):
        '''periodically sends a keepalive query to prevent the resolver's idle timeout
        from closing the connection. sends on the best-performing provider.'''
        keepalive_interval = self.DNSRelay.keepalive_interval
        keepalive_timer = self._keepalive_event.wait
        keepalive_continue = self._keepalive_event.clear

        relay_add = self.relay.add

        for _ in RUN_FOREVER():
            if keepalive_timer(keepalive_interval):
                keepalive_continue()
            else:
                relay_add(self._dns_packet(KEEP_ALIVE_DOMAIN, keepalive=True))
                Log.debug(f'[keepalive][{keepalive_interval}] Added to relay queue')

    @looper(FIVE_SEC)
    def _fail_detection(self):
        '''check all active providers for failure conditions. a provider that has
        sent HEARTBEAT_FAIL_LIMIT queries without a response in the last FIVE_SEC
        is marked as down and removed from the pool. also checks for servers that
        have recovered (Reachability marked them up) and adds them to the pool.'''
        now = fast_time()
        with self._providers_lock:
            for provider in list(self._providers):
                if (not provider.is_active):
                    self._providers.remove(provider)
                    continue

                if (now - provider.last_rcvd >= FIVE_SEC and provider.send_cnt >= HEARTBEAT_FAIL_LIMIT):
                    Log.verbose(f'[{provider.server_ip}] marking DOWN (fail detection)')
                    self.mark_server_down(remote_server=provider.server_ip)
                    provider.sock.close()
                    provider.sock = None
                    self._providers.remove(provider)

        with self._providers_lock:
            if (not self._providers):
                self.DNSRelay.tls_up = False

        # pick up any servers that Reachability has marked as recovered
        for tls_server in self.DNSRelay.dns_servers:
            ip = tls_server['ip']
            if (not tls_server[self._protocol]):
                continue
            with self._providers_lock:
                already = any(p.server_ip == ip and p.is_active for p in self._providers)
            if (not already):
                Log.verbose(f'[{ip}] server recovered, adding to pool')
                self._establish_connections()
                break


class Reachability:
    '''this class is used to determine whether a remote dns server has recovered from an outage or
    slow response times. backoff is applied so downed servers aren't hammered with connection
    attempts every cycle.'''

    __slots__ = (
        '_protocol', 'DNSRelay', '_initialize',


        '_tls_context', '_udp_query',
        '_backoff', '_backoff_next'
    )

    def __init__(self, protocol, DNSRelay):
        self._protocol = protocol
        self.DNSRelay = DNSRelay

        self._initialize = Initialize(DNSRelay.__name__)

        self._tls_context = _build_tls_context()

        self._backoff = {}
        self._backoff_next = {}

    @classmethod
    def run(cls, DNSServer):
        '''starting remote server responsiveness detection as a thread. the remote servers will only be checked for
        connectivity if they are marked as down during the polling interval.'''

        # initializing tls instance and starting thread
        reach_tls = cls(PROTO.DNS_TLS, DNSServer)
        t = threading.Thread(target=reach_tls.tls)
        t.daemon = True
        t.start()

        reach_tls._initialize.wait_for_threads(count=1)

    @looper(FIVE_SEC)
    def tls(self):
        now = fast_time()

        for secure_server in self.DNSRelay.dns_servers:
            ip = secure_server['ip']

            # no check needed if server/proto is known up
            if (secure_server[self._protocol]):
                self._backoff.pop(ip, None)
                self._backoff_next.pop(ip, None)
                continue

            # backoff: skip check if not enough time has passed since last attempt
            if ip in self._backoff_next and now < self._backoff_next[ip]:
                continue

            Log.debug(f'[{ip}/{self._protocol.name}] Checking reachability of remote DNS server.')

            # if server responds to connection attempt, it will be marked as available
            if self._tls_reachable(ip):
                secure_server[PROTO.DNS_TLS] = True
                self.DNSRelay.tls_up = True

                self._backoff.pop(ip, None)
                self._backoff_next.pop(ip, None)

                Log.system(f'[{ip}/{self._protocol.name}] DNS server is reachable.')
            else:
                self._backoff[ip] = min(self._backoff.get(ip, FIVE_SEC) * 2, THIRTY_SEC)
                self._backoff_next[ip] = now + self._backoff[ip]
                Log.verbose(f'[{ip}] reachability failed, next check in {self._backoff[ip]}s')

        self._initialize.done()

    def _tls_reachable(self, secure_server):
        sock = socket(AF_INET, SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)

        secure_socket = self._tls_context.wrap_socket(sock, server_hostname=secure_server)
        try:
            secure_socket.connect((secure_server, PROTO.DNS_TLS))
        except OSError:
            return False

        else:
            return True

        finally:
            secure_socket.close()
