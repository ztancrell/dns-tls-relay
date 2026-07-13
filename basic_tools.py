#!/usr/bin/env python3

import os
import json

from cli_colors import CLIColors

from datetime import datetime, timezone

from dns_tls_constants import *

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

    @classmethod
    def setup(cls, *, console, verbose, debug=False):
        # define function to print log message. this will overload verbose function if enabled.
        if (verbose):

            @classmethod
            def func(cls, thing_to_print):
                CLIColors.print_ok(f'[{cls.time()}][verbose]{thing_to_print}')

            # overloading verbose method with newly defined function.
            cls.verbose = func

        if (debug):

            @classmethod
            def func(cls, thing_to_print):
                CLIColors.print_info(f'[{cls.time()}][debug]{thing_to_print}')

            cls.debug = func

        if (console):

            @classmethod
            def func(cls, thing_to_print):
                CLIColors.print_header(f'[{cls.time()}][console]{thing_to_print}')

            # overloading console method with newly defined function.
            cls.console = func

    @classmethod
    def system(cls, msg):
        console_log(f'[{cls.time()}][system]{msg}')

    @classmethod
    def console(cls, msg):
        pass

    @classmethod
    def error(cls, msg):
        console_log(f'[{cls.time()}][error]{msg}')

    @staticmethod
    def verbose(msg):
        pass

    @staticmethod
    def debug(msg):
        pass

    @staticmethod
    def time(tz=timezone.utc):
        xt = datetime.now(tz).timetuple()

        return f'{xt.tm_mon}/{xt.tm_mday} {xt.tm_hour}:{xt.tm_min}:{xt.tm_sec}'
