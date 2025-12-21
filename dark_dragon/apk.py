import os
import re
import zipfile
import shutil
from .utils import console, ScannerUtils

class ApkAnalyzer:
    @staticmethod
    def unzip_apk(apk_path, extract_to):
        if not os.path.exists(apk_path):
            console.print(f"[red][!] Error: APK file '{apk_path}' not found![/red]")
            return False
        if os.path.exists(extract_to):
            console.print(f"[yellow][!] Warning: folder '{extract_to}' exists, removing...[/yellow]")
            shutil.rmtree(extract_to)
        try:
            with zipfile.ZipFile(apk_path, 'r') as zip_ref:
                zip_ref.extractall(extract_to)
            console.print(f"[green][+] APK extracted to: {extract_to}[/green]")
            return True
        except Exception as e:
            console.print(f"[red][!] Error extracting APK: {e}[/red]")
            return False

    @staticmethod
    def read_all_files(folder):
        texts = []
        for root, dirs, files in os.walk(folder):
            for file in files:
                path = os.path.join(root, file)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        texts.append(f.read())
                except:
                    pass
        return texts

    @staticmethod
    def extract_domains_urls(texts):
        # Regex to match URLs: http or https, followed by non-whitespace/quote characters
        pattern_url = re.compile(r'https?://[^\s"\'<>]+')
        # Updated regex to support more TLDs and fix partial matches (e.g. .co.uk)
        # Simplified: match alphanum/dash dot alphanum/dash, length 2+
        pattern_domain = re.compile(r'(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}')
        urls = set()
        domains = set()
        for text in texts:
            for url in pattern_url.findall(text):
                urls.add(url.strip())
            for dom in pattern_domain.findall(text):
                domains.add(dom.strip())
        return (urls, domains)

    @staticmethod
    def extract_keywords(texts):
        keywords = ['cdn', 'api', 'host', 'endpoint', 'payment', 'pay', 'billing', 'checkout', '.alicdn', '.mobily']
        found = set()
        for text in texts:
            text_lower = text.lower()
            for kw in keywords:
                if kw in text_lower:
                    found.add(kw)
        return found

    @staticmethod
    def extract_payment_urls(urls):
        payment_keys = ['pay', 'payment', 'checkout', 'billing']
        payments = set()
        for url in urls:
            for key in payment_keys:
                if key in url.lower():
                    payments.add(url)
        return payments

    @staticmethod
    def check_cdn(domain):
        cdn_keywords = ['alicdn', 'akamai', 'cloudflare', 'fastly', 'amazon', 'edgekey', 'cdn']
        for kw in cdn_keywords:
            if kw in domain.lower():
                return True
        return False

    @staticmethod
    def save_results(folder, urls, domains, keywords, cdn_domains, payments):
        os.makedirs(folder, exist_ok=True)

        def write_list(fname, data):
             with open(os.path.join(folder, fname), 'w') as f:
                for item in sorted(data):
                    f.write(item + '\n')

        write_list('urls.txt', urls)
        write_list('domains.txt', domains)
        write_list('keywords.txt', keywords)
        write_list('cdn_domains.txt', cdn_domains)
        write_list('payment_urls.txt', payments)

    @staticmethod
    def run():
        ScannerUtils.print_banner()
        console.print(f"[red]\n    ☠️☠️☠️ APK CDN HUNTER ☠️☠️☠️\n    🔥 SCANNING APK FILE FOR SECRET DOMAINS 🔥\n    [/red]")
        apk_path = console.input(f"[cyan]🔍 Enter APK file path: [/cyan]").strip()
        result_folder = console.input(f"[cyan]💾 Enter folder name to save results: [/cyan]").strip()

        ScannerUtils.slow_print(f"[magenta][*] Extracting APK file ...[/magenta]")
        if not ApkAnalyzer.unzip_apk(apk_path, result_folder + '_extracted'):
            return

        ScannerUtils.slow_print(f"[magenta][*] Reading all files ...[/magenta]")
        texts = ApkAnalyzer.read_all_files(result_folder + '_extracted')

        ScannerUtils.slow_print(f"[magenta][*] Extracting URLs and domains ...[/magenta]")
        urls, domains = ApkAnalyzer.extract_domains_urls(texts)

        ScannerUtils.slow_print(f"[magenta][*] Searching for important keywords ...[/magenta]")
        keywords = ApkAnalyzer.extract_keywords(texts)

        ScannerUtils.slow_print(f"[magenta][*] Extracting payment gateway URLs ...[/magenta]")
        payments = ApkAnalyzer.extract_payment_urls(urls)

        ScannerUtils.slow_print(f"[magenta][*] Analyzing domains and checking for CDN ...[/magenta]")
        cdn_domains = set()
        for d in domains:
            if ApkAnalyzer.check_cdn(d):
                cdn_domains.add(d)

        ScannerUtils.slow_print(f"[green][✔] Saving results ...[/green]")
        ApkAnalyzer.save_results(result_folder, urls, domains, keywords, cdn_domains, payments)

        console.print(f"[yellow]\n[✔] Scan complete! Results saved in folder: {result_folder}[/yellow]")
        console.print(f"[yellow]Check files:\n - urls.txt\n - domains.txt\n - keywords.txt\n - cdn_domains.txt\n - payment_urls.txt\n[/yellow]")
        console.input('Press Enter to return to main menu...')
