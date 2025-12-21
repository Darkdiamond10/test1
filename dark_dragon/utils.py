import os
import sys
import time
import threading
from colorama import init, Fore, Style
from rich.console import Console

# Initialize colorama
init(autoreset=True)

# Initialize Rich Console
console = Console()

# --- Constants & Configuration ---
# Colors for raw print if needed (prefer Rich where possible)
G = Fore.GREEN
R = Fore.RED
C = Fore.CYAN
YELLOW = Fore.YELLOW
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL

BANNER = """
[bold red]
________               ______  _______
___  __ \_____ _________  /__  __  __ \_____________________________________
__  / / /  __ `/_  ___/  //_/  / / /  /_  ___/  __ `/_  __ `/  __ \_  __ \\
_  /_/ // /_/ /_  /   _  ,<   _  /_/ /_  /   / /_/ /_  /_/ // /_/ /  / / /
/_____/ \__,_/ /_/    /_/|_|  /_____/ /_/    \__,_/ _\__, / \____//_/ /_/
                                                    /____/
[/bold red]
[bold magenta]        >>> Network Security Analysis Tool <<<[/bold magenta]
"""

# Global Lock for thread-safe printing (used by legacy threads, if any)
print_lock = threading.Lock()

class ScannerUtils:
    @staticmethod
    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def check_file_exists(filepath):
        return os.path.isfile(filepath)

    @staticmethod
    def print_banner():
        ScannerUtils.clear_screen()
        console.print(BANNER)

    @staticmethod
    def slow_print(text, delay=0.03):
        """Prints text slowly for effect."""
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(delay)
        print()
