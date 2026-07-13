#!/usr/bin/env python3

import os
import sys
import time
import argparse

from ipaddress import IPv4Address

from dns_tls_constants import hard_out, ONE_SEC
from basic_tools import Log
from dns_tls_relay import DNSRelay
from cli_colors import CLIColors

# override for testing arguments
DISABLED = False

# must support DNS over TLS (not https/443, tcp/853). deliberately defaulting to two DIFFERENT providers
# (Cloudflare + Quad9) rather than two IPs of the same provider, so no single company ends up with visibility
# into 100% of this relay's query history (TLSRelay randomizes which one is preferred on each new connection --
# see dns_tls_protocols._register_new_socket). NOTE: Quad9 filters known-malicious domains by default, so a
# domain could occasionally resolve differently depending on which provider happened to answer it.
DEFAULT_SERVER_1 = '1.1.1.1'
DEFAULT_SERVER_2 = '9.9.9.9'

# this makes me feel cool. especially when i haven't left the house in forever due to covid-19.
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


if (__name__ == '__main__'):

    if (os.getuid() or DISABLED):
        print('DoTRelay must be ran as root.')
        hard_out()

    parser = argparse.ArgumentParser(description='Privacy proxy to convert DNS:UDP to TLS w/ local record caching.')
    parser.add_argument('--version', action='version', version='v9001b')

    parser.add_argument('-l',
        metavar='listen_ip [listen_ip...]', help='List of IP Addresses to listen for requests on',
        type=IPv4Address, nargs='+', default=[IPv4Address('127.0.0.1')]
    )

    parser.add_argument('-r',
        metavar='resolver_ip', help='List of (2) IP Addresses of desired public DoT resolvers',
        type=IPv4Address, nargs=2, default=[DEFAULT_SERVER_1, DEFAULT_SERVER_2]
    )

    parser.add_argument('-k', help='Enables TLS connection keepalives', type=int, choices=[4, 6, 8], default=0)
    parser.add_argument('-c', help='Prints general messages to screen', action='store_true')
    parser.add_argument('-v', help='Prints informational messages to screen', action='store_true')
    parser.add_argument('-m',
        help='Paranoid/memory-only mode. Disables all disk persistence of the top domains cache, so no '
             'plaintext record of locally observed dns query activity can survive a restart or be recovered '
             'from this device (eg. on physical access/seizure). Top domains will not be permanently cached '
             'across restarts.',
        action='store_true'
    )

    args = parser.parse_args(sys.argv[1:])

    Log.setup(console=args.c, verbose=args.v)

    DNSRelay.dns_servers.primary['ip'] = f'{args.r[0]}'
    DNSRelay.dns_servers.secondary['ip'] = f'{args.r[1]}'

    display_banner()

    CLIColors.print_header('Starting DNS Relay...')
    DNSRelay.run(args.l, args.k, persist_top_domains=not args.m)

    # DNSRelay.run only starts background threads then returns immediately, so the main thread blocks here to keep
    # the process alive and to give us a clean, single place to intercept ctrl+c instead of relying on the
    # interpreter's default (noisy) shutdown/thread-join behavior.
    try:
        while True:
            time.sleep(ONE_SEC)
    except KeyboardInterrupt:
        CLIColors.print_header('\nShutting down DNS Relay...')
        hard_out()
