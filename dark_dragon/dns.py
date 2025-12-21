import socket
import dns.resolver
import time
from .utils import console, G, R, RESET, ScannerUtils

class DNSScanner:
    @staticmethod
    def check_dns(ip, port=53, timeout=3):
        """
        Checks if the IP has an open DNS port (UDP/TCP) and attempts a basic resolution.
        """
        results = []
        # Check UDP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            # Just sending a query might not get a response if it's restricted, but connection check on UDP is tricky.
            # We can try to resolve google.com using this IP as nameserver.

            resolver = dns.resolver.Resolver()
            resolver.nameservers = [ip]
            resolver.timeout = timeout
            resolver.lifetime = timeout

            start = time.time()
            answer = resolver.resolve('google.com', 'A')
            duration = time.time() - start

            results.append(f"{G}[+] DNS Open (UDP) - Resolved google.com in {duration:.2f}s{RESET}")
            for r in answer:
                results.append(f"    - {r}")

        except Exception as e:
            results.append(f"{R}[-] DNS Resolution (UDP) failed: {e}{RESET}")

        return "\n".join(results)

    @staticmethod
    def run_check(ip):
        console.print(f"[cyan]Scanning DNS on {ip}...[/cyan]")
        output = DNSScanner.check_dns(ip)
        console.print(output)
