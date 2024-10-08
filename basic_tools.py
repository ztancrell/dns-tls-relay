#!/usr/bin/env python3

import json

from datetime import datetime, timezone

from dns_tls_constants import *

from dnx_shell.utils.shell_colors import text, styles

def load_cache(filename):
    try:
        with open(f'{filename}.json', 'r') as settings:
            cache = json.load(settings)
    except FileNotFoundError:
        cache = {'top_domains': {}, 'filter': []}

    return cache

def write_cache(top_domains):
    with open('top_domains.json', 'r') as cache:
        f_cache = json.load(cache)

    f_cache['top_domains'] = top_domains

    with open('top_domains.json', 'w') as cache:
        json.dump(f_cache, cache, indent=4)

def looper(sleep_len):
    def decorator(loop_function):

        # pre-process logic to optimize decorated functions with NO_DELAY set
        if (sleep_len):
            def wrapper(*args):
                for _ in RUN_FOREVER():
                    loop_function(*args)

                    fast_sleep(sleep_len)

        else:
            def wrapper(*args):
                for _ in RUN_FOREVER():
                    loop_function(*args)

        return wrapper
    return decorator


class Log:

    # color coded log messages
    # Yellow = VERBOSE
    # Cyan = CONSOLE
    # LightGrey = SYSTEM
    # Red = ERROR

    @classmethod
    def setup(cls, *, console, verbose):
        # define function to print log message. this will overload verbose function if enabled.
        if (verbose):

            @classmethod
            def func(cls, thing_to_print):
                console_log(f'[{cls.time()}][verbose]{thing_to_print}')
                console_log(f'[{cls.time()}]' + text.yellow(f'[verbose] ') + text.lightgrey(f'{thing_to_print}'))

            # overloading verbose method with newly defined function.
            setattr(cls, 'verbose', func)

        if (console):

            @classmethod
            def func(cls, thing_to_print):
                console_log(f'[{cls.time()}][console]{thing_to_print}')
                console_log(f'[{cls.time()}]' + text.cyan(f'[console] ') + text.lightgrey(f'{thing_to_print}'))

            # overloading console method with newly defined function.
            setattr(cls, 'console', func)

    @classmethod
    def system(cls, msg):
        console_log(f'[{cls.time()}][system]{msg}')
        console_log(f'[{cls.time()}]' + text.lightgrey(f'[system] ') + f'{msg}')

    @classmethod
    def console(cls, msg):
        pass

    @classmethod
    def error(cls, msg):
        console_log(f'[{cls.time()}][error]{msg}')
        console_log(f'[{cls.time()}]' + text.red(f'[error] ') + f'{msg}')

    @staticmethod
    def verbose(msg):
        pass

    @staticmethod
    def time(tz=timezone.utc):
        xt = datetime.now(tz).timetuple()

        return f'{xt.tm_mon}/{xt.tm_mday} {xt.tm_hour}:{xt.tm_min}:{xt.tm_sec}'
