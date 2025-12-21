import os
import sys
import time
import threading
import ipaddress
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

class TargetUtils:
    @staticmethod
    def _iter_targets(ranges_input):
        """Helper to iterate over targets whether it's a list or a file path."""
        if isinstance(ranges_input, str):
            # Treat as file path
            if os.path.isfile(ranges_input):
                with open(ranges_input, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            yield line
            else:
                # Treat as a single target or CIDR string if not a file
                yield ranges_input.strip()
        else:
            # Treat as list
            for item in ranges_input:
                yield item.strip()

    @staticmethod
    def generate_targets(ranges_input):
        """Generator that yields IPs one by one to save memory."""
        for net in TargetUtils._iter_targets(ranges_input):
            try:
                network = ipaddress.IPv4Network(net, strict=False)
                for ip in network:
                    yield str(ip)
            except ValueError:
                # Assume it's a domain if not a valid IP/CIDR
                yield net
            except Exception as e:
                console.print(f"{R}[!] Invalid range: {net} ({e}){RESET}")

    @staticmethod
    def count_targets(ranges_input):
        count = 0
        for net in TargetUtils._iter_targets(ranges_input):
            try:
                network = ipaddress.IPv4Network(net, strict=False)
                count += network.num_addresses
            except ValueError:
                # Count as 1 for domain
                count += 1
            except:
                pass
        return count
