import sys


class CLIColors:
    HEADER = "\033[95m"
    OKBLUE = "\033[94m"
    OKGREEN = "\033[92m"
    WARNING = "\033[93m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"

    _enabled = sys.stderr.isatty()

    @classmethod
    def enable(cls, enabled):
        cls._enabled = enabled

    @classmethod
    def _colorize(cls, color, text):
        if cls._enabled:
            return f"{color}{text}{cls.ENDC}"
        return text

    @classmethod
    def print_header(cls, text):
        print(cls._colorize(cls.HEADER, text))

    @classmethod
    def print_ok(cls, text):
        print(cls._colorize(cls.OKGREEN, text))

    @classmethod
    def print_warning(cls, text):
        print(cls._colorize(cls.WARNING, text))

    @classmethod
    def print_error(cls, text):
        print(cls._colorize(cls.FAIL, text))

    @classmethod
    def print_info(cls, text):
        print(cls._colorize(cls.OKBLUE, text))
