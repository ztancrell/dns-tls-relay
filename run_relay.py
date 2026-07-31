#!/usr/bin/env python3

import os
import sys
import time
import signal
import socket
import argparse

from ipaddress import IPv4Address

from dns_tls_constants import hard_out, ONE_SEC, KEEP_ALIVE_DOMAIN
from basic_tools import Log, console_log
from dns_tls_relay import DNSRelay, RateLimiter
from dns_tls_protocols import TLSRelay
from cli_colors import CLIColors

# must support DNS over TLS (not https/443, tcp/853). deliberately defaulting to two DIFFERENT providers
# (Cloudflare + Quad9) rather than two IPs of the same provider, so no single company ends up with visibility
# into 100% of this relay's query history. Quad9 filters known-malicious domains by default, so a domain
# could occasionally resolve differently depending on which provider happened to answer it.
DEFAULT_SERVER_1 = '1.1.1.1'
DEFAULT_SERVER_2 = '9.9.9.9'


def sd_notify(state):
    notify_sock = os.environ.get('NOTIFY_SOCKET')
    if not notify_sock:
        return
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(notify_sock)
        sock.sendall(state.encode())
        sock.close()
    except OSError:
        pass


def display_banner():
    print('@@@@@@@    @@@@@@   @@@@@@@     @@@@@@@   @@@@@@@@  @@@        @@@@@@   @@@ @@@')
    print('@@@@@@@@  @@@@@@@@  @@@@@@@     @@@@@@@@  @@@@@@@@  @@@       @@@@@@@@  @@@ @@@')
    print('@@!  @@@  @@!  @@@    @@!       @@!  @@@  @@!       @@!       @@!  @@@  @@! !@@')
    print('!@!  @!@  !@!  @!@    !@!       !@!  @!@  !@!       !@!       !@!  @!@  !@! @!!')
    print('@!@  !@!  @!@  !@!    @!!       @!@!!@!   @!!!:!    @!!       @!@!@!@!   !@!@! ')
    print('!@!  !!!  !@!  !!!    !!!       !!@!@!    !!!!!:    !!!       !!!@!!!!    @!!! ')
    print('!!:  !!!  !!:  !!!    !!:       !!: :!!   !!:       !!:       !!:  !!!    !!:  ')
    print(':!:  !:!  :!:  !:!    :!:       :!:  !:!  :!:        :!:      :!:  !:!    :!:  ')
    print(' :::: ::  ::::: ::     ::       ::   :::   :: ::::   :: ::::  ::   :::     ::  ')
    print(':: :  :    : :  :      :         :   : :  : :: ::   : :: : :   :   : :     :   ')
    print('by DOWRIGHT | https://github.com/dowrighttv                    ^^^^ for fun ^_^')
    print('===============================================================================')
    time.sleep(1)
    CLIColors.print_header('starting...')
    time.sleep(.5)


def load_config_from_file(config_path):
    '''load YAML config file, return dict or None.'''
    try:
        import yaml
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        console_log(f'[config] file not found: {config_path}')
    except Exception as E:
        console_log(f'[config] error loading {config_path}: {E}')
    return None


def apply_config(args, config):
    '''apply config file values as overrides to parsed args.'''
    if config is None:
        return args

    cfg = config.get('relay', config)
    if 'listen' in cfg:
        args.l = [IPv4Address(ip) for ip in cfg['listen']]
    if 'resolvers' in cfg:
        args.r = [IPv4Address(ip) for ip in cfg['resolvers'][:2]]
    if 'keepalive' in cfg:
        args.k = cfg['keepalive']
    if 'keepalive_domain' in cfg:
        args.keepalive_domain = cfg['keepalive_domain']
    if 'workers' in cfg:
        args.workers = cfg['workers']
    if 'console' in cfg:
        args.c = cfg['console']
    if 'verbose' in cfg:
        args.v = cfg['verbose']
    if 'debug' in cfg:
        args.d = cfg['debug']
    if 'memory_only' in cfg:
        args.m = cfg['memory_only']

    # dnssec is top-level in the config file (not under relay)
    if 'dnssec' in config:
        args.dnssec = config['dnssec']
    elif 'dnssec' in cfg:
        args.dnssec = cfg['dnssec']

    return args


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description='Privacy proxy to convert DNS:UDP to TLS w/ local record caching.')
    parser.add_argument('--version', action='version', version='v9001b')

    parser.add_argument('-l',
        metavar='listen_ip [listen_ip...]', help='List of IP Addresses to listen for requests on',
        type=IPv4Address, nargs='+', default=[IPv4Address('127.0.0.1')]
    )

    parser.add_argument('-r',
        metavar='resolver_ip resolver_ip', help='List of (2) IP Addresses of desired public DoT resolvers',
        type=IPv4Address, nargs=2, default=[DEFAULT_SERVER_1, DEFAULT_SERVER_2]
    )

    parser.add_argument('-k', help='Enables TLS connection keepalives', type=int, choices=[4, 6, 8], default=0)
    parser.add_argument('-c', help='Prints general messages to screen', action='store_true')
    parser.add_argument('-v', help='Prints informational messages to screen', action='store_true')
    parser.add_argument('-d', '--debug',
        help='Prints debug-level messages to screen (blue). Independent of -v; use both to see all output levels.',
        action='store_true'
    )
    parser.add_argument('-m',
        help='Paranoid/memory-only mode. Disables all disk persistence of the top domains cache.',
        action='store_true'
    )
    parser.add_argument('--force',
        help='Allow running without root (for testing).',
        action='store_true'
    )
    parser.add_argument('--config',
        metavar='PATH', help='Path to YAML configuration file.',
        default=None
    )
    parser.add_argument('--workers',
        metavar='N', help='Max thread pool workers (default: 32).',
        type=int, default=32
    )
    parser.add_argument('--keepalive-domain',
        metavar='DOMAIN', help='Domain used for TLS keepalive queries.',
        default=KEEP_ALIVE_DOMAIN
    )
    parser.add_argument('--daemonize',
        help='Daemonize the process (fork to background).',
        action='store_true'
    )
    parser.add_argument('--syslog',
        help='Log to syslog instead of stderr.',
        action='store_true'
    )
    parser.add_argument('--dnssec',
        action=argparse.BooleanOptionalAction,
        default=True,
        help='Enforce DNSSEC at the upstream resolver: set the EDNS DO bit and force CD=0 on '
             'all upstream queries so the validating resolver always checks signatures (returns '
             'SERVFAIL on bogus data). This relay relies on the upstream resolver for validation; '
             'it does not verify RRSIG chains itself. Use --no-dnssec to disable.'
    )
    parser.add_argument('--rate-limit',
        metavar='QPS', help='Max queries per second per client IP (default: 50).',
        type=int, default=50
    )
    parser.add_argument('--rate-burst',
        metavar='N', help='Max burst size per client IP (default: 100).',
        type=int, default=100
    )
    parser.add_argument('--metrics-port',
        metavar='PORT', help='Prometheus metrics HTTP port (default: 9190).',
        type=int, default=9190
    )
    parser.add_argument('--color',
        help='Force colored output (auto-detected by default).',
        action='store_true', default=None
    )
    parser.add_argument('--no-color',
        help='Disable colored output.',
        action='store_true', default=None
    )

    args = parser.parse_args(argv)

    config = None
    if args.config:
        config = load_config_from_file(args.config)
        args = apply_config(args, config)

    return args, config


def main():
    args, config = parse_args()

    if (os.getuid() and not args.force):
        console_log('DoTRelay must be run as root (or use --force for testing).')
        hard_out()

    if args.no_color:
        CLIColors.enable(False)
    elif args.color:
        CLIColors.enable(True)

    Log.setup(console=args.c, verbose=args.v, debug=args.debug)

    DNSRelay.dns_servers.primary['ip'] = f'{args.r[0]}'
    DNSRelay.dns_servers.secondary['ip'] = f'{args.r[1]}'
    DNSRelay._max_workers = args.workers
    DNSRelay.keepalive_domain = args.keepalive_domain

    if args.dnssec:
        DNSRelay._dnssec_enabled = True
        import dns_tls_packets as _packets
        _packets._dnssec_enabled = True
        Log.system('DNSSEC enforcement enabled (DO bit + CD=0; upstream validation)')

    DNSRelay._rate_limiter = RateLimiter(rate=args.rate_limit, burst=args.rate_burst)
    DNSRelay._metrics_port = args.metrics_port

    display_banner()

    CLIColors.print_header('Starting DNS Relay...')
    DNSRelay.run(args.l, args.k, persist_top_domains=not args.m)
    sd_notify('READY=1')

    _shutdown_state = [0]

    def _shutdown(signum, frame):
        _shutdown_state[0] += 1
        sd_notify('STOPPING=1')
        if _shutdown_state[0] > 1:
            CLIColors.print_header('\nForcing immediate exit...')
            hard_out()

        CLIColors.print_header('\nShutting down DNS Relay...')
        TLSRelay.shutdown()
        DNSRelay.shutdown()
        hard_out()

    def _reload_config(signum, frame):
        CLIColors.print_header('\nReloading configuration...')
        new_args, new_config = parse_args(sys.argv[1:])
        if new_config is not None:
            DNSRelay._max_workers = new_args.workers
            DNSRelay.keepalive_domain = new_args.keepalive_domain
            DNSRelay._rate_limiter = RateLimiter(rate=new_args.rate_limit, burst=new_args.rate_burst)
            DNSRelay.keepalive_interval = new_args.k
            Log.setup(console=new_args.c, verbose=new_args.v, debug=new_args.debug)
            CLIColors.print_header('Configuration reloaded.')

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGHUP, _reload_config)

    try:
        while True:
            time.sleep(ONE_SEC)
    except KeyboardInterrupt:
        _shutdown(None, None)


if (__name__ == '__main__'):
    main()
