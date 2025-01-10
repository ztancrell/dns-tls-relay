class CLIColors:
    HEADER = "\033[95m"  # Magenta
    OKBLUE = "\033[94m"  # Blue
    OKGREEN = "\033[92m"  # Green
    WARNING = "\033[93m"  # Yellow
    FAIL = "\033[91m"  # Red
    ENDC = "\033[0m"  # Reset
    BOLD = "\033[1m"  # Bold
    UNDERLINE = "\033[4m"  # Underline

    @staticmethod
    def print_header(text):
        print(f"{CLIColors.HEADER}{text}{CLIColors.ENDC}")

    @staticmethod
    def print_ok(text):
        print(f"{CLIColors.OKGREEN}{text}{CLIColors.ENDC}")

    @staticmethod
    def print_warning(text):
        print(f"{CLIColors.WARNING}{text}{CLIColors.ENDC}")

    @staticmethod
    def print_error(text):
        print(f"{CLIColors.FAIL}{text}{CLIColors.ENDC}")

    @staticmethod
    def print_info(text):
        print(f"{CLIColors.OKBLUE}{text}{CLIColors.ENDC}")
