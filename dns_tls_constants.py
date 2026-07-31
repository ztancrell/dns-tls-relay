#!/usr/bin/env python3

from struct import Struct as _Struct
from enum import IntEnum as _IntEnum
from collections import namedtuple as _namedtuple

# re-exported from basic_tools for backward compatibility with wildcard imports
from basic_tools import fast_time, fast_sleep, RUN_FOREVER, console_log, hard_out, btoia, byte_join

CONNECT_TIMEOUT = 2
RELAY_TIMEOUT = 30

# general settings
MINIMUM_TTL = 300
DEFAULT_TTL = 3600
MAX_A_RECORD_COUNT = 3
HEARTBEAT_FAIL_LIMIT = 3
TOP_DOMAIN_COUNT = 20
KEEP_ALIVE_DOMAIN = 'dnxfirewall.com'

# static, non-sensitive config (safe to version control) used to exclude noisy/rotating hostnames from ever being
# considered for the top domains permanent cache. matched against individual dot separated labels of the domain
# (a label "starts with" one of these), not a raw substring-anywhere check -- eg. 'api' matches the label in
# "api.example.com" or "api2.example.com" but NOT an unrelated domain that merely contains "api" mid word.
# purely numeric labels (eg. rotating ntp pool/shard hosts like "0.pool.ntp.org") are excluded separately/always,
# so bare digits do not need to (and should not) appear in this list.
DOMAIN_FILTER = (
    '-', 'test', 'detect', 'mozilla', 'oscp', 'ntp', 'api', 'akamai', 'cdn',
    'microsoft', 'windows', 'ubuntu', 'dns', 'http', 'telemetry', 'wpad', 'ssl',
)

# top domains heuristic self-tuning safety rails (NOT tuned operating points -- the live decay rate adapts itself
# between these bounds based on observed top domain churn/stability, so these just prevent runaway degenerate
# behavior rather than needing to be "the right" value for any particular network/traffic volume).
TOP_DOMAIN_DECAY_MIN = 0.5   # fastest allowed forgetting rate (most responsive to change)
TOP_DOMAIN_DECAY_MAX = 0.95  # slowest allowed forgetting rate (most resistant to noise)

# a domain must retain at least this fraction of the current leading domain's (decayed) count to remain eligible
# for the permanent cache. relative/self-scaling instead of an absolute magic number so it behaves sensibly
# regardless of whether a network generates tens or tens of thousands of lookups per cycle.
TOP_DOMAIN_MIN_SHARE = 0.1

# multi-timeframe scoring: burst counter decays fast to respond to traffic spikes; stability counter decays
# slowly to recognize long-term patterns. combined score = burst + stability.
BURST_DECAY_RATE = 0.3         # fast decay for burst responsiveness (captures spikes)
STABILITY_DECAY_RATE = 0.95    # slow decay for long-term pattern recognition
BURST_ADAPT_MIN = 0.1          # burst can't decay faster than this
BURST_ADAPT_MAX = 0.5          # burst can't decay slower than this

# negative caching: remembers nxdomain/servfail responses so repeat lookups for the same nonexistent
# domain don't hit the upstream resolver again before the negative TTL expires.
NEGATIVE_CACHE_TTL = 30        # seconds to cache nxdomain/servfail
NEGATIVE_CACHE_CLEAN_INTERVAL = 300  # seconds between negative cache expiry sweeps

# EDNS0 (RFC 6891) option codes relevant to the upstream/WAN facing leg of the relay.
EDNS_ECS_CODE = 8       # RFC 7871 Client Subnet -- must be stripped, this relay exists to NOT reveal that.
EDNS_PADDING_CODE = 12  # RFC 7830 Padding

# RFC 8467 recommended padding block size for dns queries sent over a TLS/HTTPS transport -- queries are
# padded up to the next multiple of this so raw query length alone leaks less about which domain is being
# resolved to anything observing the encrypted wire.
EDNS_PADDING_BLOCK = 128

# advertised UDP payload size used only when the relay synthesizes a fresh OPT record from scratch (ie. the
# LAN client's query didn't already include one). has no real effect here since this leg is TCP/TLS, not UDP.
EDNS_DEFAULT_UDP_SIZE = 4096

NOT_VALID = -1
NULL_ADDR = (None, None)

# times
NO_DELAY = 0
MSEC = .001
ONE_SEC = 1
FIVE_SEC = 5
TEN_SEC = 10
THIRTY_SEC = 30
THREE_MIN = 180
FIVE_MIN = 300

# namedtuple
RELAY_CONN = _namedtuple('relay_conn', 'remote_ip sock send recv version')
DNS_CACHE = _namedtuple('dns_cache', 'ttl records')
CACHED_RECORD = _namedtuple('cached_record', 'expire ttl records')
DNS_SERVERS = _namedtuple('dns_server', 'primary secondary')

# SOCKET
L_SOCK = _namedtuple('listener_socket', 'ip socket sendto recvfrom')

# COMPILED Structs
dns_header_unpack = _Struct('!6H').unpack
dns_header_pack   = _Struct('!6H').pack

resource_record_pack = _Struct('!3HLH4s').pack

short_unpackf = _Struct('!H').unpack_from

byte_pack = _Struct('!B').pack
short_unpack = _Struct('!H').unpack
short_pack   = _Struct('!H').pack
long_pack    = _Struct('!L').pack
long_unpack  = _Struct('!L').unpack

double_short_unpack = _Struct('!2H').unpack_from
double_short_pack   = _Struct('!2H').pack


# enums
class PROTO(_IntEnum):
    NOT_SET = 0
    TCP = 6
    DNS = 53
    DNS_TLS = 853

class DNS(_IntEnum):
    ROOT  = 0
    A     = 1
    NS    = 2
    CNAME = 5
    SOA   = 6
    PTR   = 12
    MX    = 15
    TXT   = 16
    AAAA  = 28
    OPT   = 41
    DS    = 43
    RRSIG = 46
    NSEC  = 47
    DNSKEY = 48
    NSEC3 = 50

    QUERY = 0  # alias
    TOP_DOMAIN = 1  # alias
    KEEPALIVE  = 69
    RESPONSE   = 128
