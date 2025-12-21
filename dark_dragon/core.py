import sys
import asyncio
from .utils import ScannerUtils, console, C, RESET, R
from .network import NetworkScanner
from .cidr import CIDRScanner
from .recon import SubdomainRecon
from .apk import ApkAnalyzer
from .dns import DNSScanner

class DarkDragonCore:
    def __init__(self):
        self.running = True

    def main_menu(self):
        while self.running:
            ScannerUtils.print_banner()
            console.print(f"""
    [1] SNI Scanner
    [2] CIDR Scanner
    [3] Subdomain Recon
    [4] APK Analysis
    [5] DNS Scanner
    [0] Exit
            """)
            choice = console.input("[cyan]Enter choice: [/cyan]").strip()

            if choice == '1':
                self.sni_menu()
            elif choice == '2':
                self.cidr_menu()
            elif choice == '3':
                self.recon_menu()
            elif choice == '4':
                self.apk_menu()
            elif choice == '5':
                self.dns_menu()
            elif choice == '0':
                console.print("[red]Exiting...[/red]")
                self.running = False
            else:
                console.input("[red]Invalid choice. Press Enter...[/red]")
              
    def sni_menu(self):
        ScannerUtils.clear_screen()
        console.print("[cyan]--- SNI / SSL / Proxy Scanner ---[/cyan]")
        domain = console.input("Target Domain/IP: ").strip()
        try:
            port = int(console.input("Port (443): ").strip() or "443")
        except:
            port = 443

        console.print(f"\n[1] Scan SNI\n[2] Scan SSL\n[3] Scan Proxy\n[4] Scan HTTP\n[5] Scan HTTPS\n")
        mode = console.input("Select Mode: ").strip()

        if mode == '1':
            res = NetworkScanner.scan_sni(domain, port)
        elif mode == '2':
            res = NetworkScanner.scan_ssl(domain, port)
        elif mode == '3':
            res = NetworkScanner.scan_proxy(domain, port)
        elif mode == '4':
            res = NetworkScanner.scan_http(domain, port)
        elif mode == '5':
            res = NetworkScanner.scan_https(domain, port)
        else:
            console.print("[red]Invalid mode[/red]")
            console.input("Press Enter...")
            return

        if res[0]:
            console.print(f"[green]{res[1]}[/green]")
        else:
            console.print(f"[red]{res[1]}[/red]")
        console.input("\nPress Enter...")

    def cidr_menu(self):
        ScannerUtils.clear_screen()
        console.print("[cyan]--- CIDR Scanner (Async) ---[/cyan]")
        ranges = console.input("Enter IP ranges (comma separated): ").strip().split(',')
        try:
            port = int(console.input("Port (80/443): ").strip())
        except:
            console.print("[red]Invalid port[/red]")
            return

        try:
            threads = int(console.input("Concurrency (default 100): ").strip() or "100")
        except:
            threads = 100

        output = console.input("Output file (results.txt): ").strip() or "results.txt"

        scanner = CIDRScanner(port, threads, output)
        scanner.run(ranges)
        console.input("\nPress Enter...")

    def recon_menu(self):
        ScannerUtils.clear_screen()
        console.print("[cyan]--- Subdomain Recon (Async) ---[/cyan]")
        domain = console.input("Target Domain: ").strip()
        api_key = console.input("VirusTotal API Key (optional): ").strip()

        # Run async recon
        subs = asyncio.run(SubdomainRecon.extract_subdomains(domain, api_key))

        save = console.input("Save to file? (y/N): ").strip().lower()
        if save == 'y':
            fname = console.input("Filename: ").strip()
            SubdomainRecon.save_domains_to_file(subs, fname)

        console.input("\nPress Enter...")

    def apk_menu(self):
        # ApkAnalyzer has its own internal interaction logic in the original code
        ApkAnalyzer.run()

    def dns_menu(self):
        ScannerUtils.clear_screen()
        console.print("[cyan]--- DNS Scanner ---[/cyan]")
        ip = console.input("Target IP: ").strip()
        DNSScanner.run_check(ip)
        console.input("\nPress Enter...")
