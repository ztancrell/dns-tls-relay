#!/usr/bin/env python3

import os
import json

import os as _os
import time as _time

from functools import partial as _partial
from itertools import repeat as _repeat

from cli_colors import CLIColors

from datetime import datetime, timezone

fast_time = _time.time
fast_sleep = _time.sleep

RUN_FOREVER = _partial(_repeat, 1)
console_log = _partial(print, flush=True)
hard_out = _partial(_os._exit, 1)
btoia = _partial(int.from_bytes, byteorder='big', signed=False)

byte_join = b''.join

def load_cache(filename):
    '''loads named json cache file from disk. returns sane defaults if the file is missing, unreadable, or
    contains invalid json (eg. corrupted by an unclean shutdown) instead of raising.

    NOTE: this file is purely runtime state (locally observed dns query activity) and is intentionally NOT
    tracked in version control -- see .gitignore. static/non-sensitive config like the domain filter list lives
    in dns_tls_constants.py instead.'''
    try:
        with open(f'{filename}.json', 'r') as settings:
            cache = json.load(settings)
    except FileNotFoundError:
        cache = {'top_domains': {}}
    except (ValueError, OSError) as E:
        console_log(f'[cache] failed to load {filename}.json, falling back to defaults. {E}')
        cache = {'top_domains': {}}

    # tolerate/ignore a leftover 'filter' key from the older on disk format -- it is no longer read from here,
    # so no explicit migration step is needed, it will simply not be re-written on the next write_cache() call.
    cache.setdefault('top_domains', {})

    return cache

def write_cache(top_domains):
    '''persists top_domains into the on disk cache file. write is done atomically (temp file + rename) so a
    crash/power loss mid write cannot corrupt the cache.'''
    tmp_file = 'top_domains.json.tmp'
    with open(tmp_file, 'w') as cache:
        json.dump({'top_domains': top_domains}, cache, indent=4)
        cache.flush()
        os.fsync(cache.fileno())

    os.replace(tmp_file, 'top_domains.json')

def looper(sleep_len):
    def decorator(loop_function):

        # pre-process logic to optimize decorated functions with NO_DELAY set
        if (sleep_len):
            def wrapper(*args):
                for _ in RUN_FOREVER():
                    try:
                        loop_function(*args)
                    except Exception as E:
                        Log.error(f'[looper/{loop_function.__name__}] {E}')

                    fast_sleep(sleep_len)

        else:
            def wrapper(*args):
                for _ in RUN_FOREVER():
                    try:
                        loop_function(*args)
                    except Exception as E:
                        Log.error(f'[looper/{loop_function.__name__}] {E}')

        return wrapper
    return decorator


class Log:
    _verbose_enabled = False
    _debug_enabled = False
    _console_enabled = False

    @classmethod
    def setup(cls, *, console, verbose, debug=False):
        cls._verbose_enabled = verbose
        cls._debug_enabled = debug
        cls._console_enabled = console

    @classmethod
    def system(cls, msg):
        console_log(f'[{cls.time()}][system]{msg}')

    @classmethod
    def console(cls, msg):
        if cls._console_enabled:
            CLIColors.print_header(f'[{cls.time()}][console]{msg}')

    @classmethod
    def error(cls, msg):
        console_log(f'[{cls.time()}][error]{msg}')

    @classmethod
    def verbose(cls, msg):
        if cls._verbose_enabled:
            CLIColors.print_ok(f'[{cls.time()}][verbose]{msg}')

    @classmethod
    def debug(cls, msg):
        if cls._debug_enabled:
            CLIColors.print_info(f'[{cls.time()}][debug]{msg}')

    @staticmethod
    def time(tz=timezone.utc):
        xt = datetime.now(tz).timetuple()

        return f'{xt.tm_mon}/{xt.tm_mday} {xt.tm_hour}:{xt.tm_min}:{xt.tm_sec}'
