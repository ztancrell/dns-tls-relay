#!/usr/bin/env python3

import os as _os
import time as _time

from functools import partial as _partial
from itertools import repeat as _repeat
from struct import Struct as _Struct
from enum import IntEnum as _IntEnum
from collections import namedtuple as _namedtuple

fast_time = _time.time
fast_sleep = _time.sleep

RUN_FOREVER = _partial(_repeat, 1)
console_log = _partial(print, flush=True)
hard_out = _partial(_os._exit, 1)
btoia = _partial(int.from_bytes, byteorder='big', signed=False)

byte_join = b''.join

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

    QUERY = 0  # alias
    TOP_DOMAIN = 1  # alias
    KEEPALIVE  = 69
    RESPONSE   = 128
