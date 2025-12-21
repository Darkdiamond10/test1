import asyncio
import aiohttp
import subprocess
import shutil
import requests
from bs4 import BeautifulSoup
from .utils import console

class SubdomainRecon:
    @staticmethod
    async def extract_subdomains(domain, virustotal_api_key=None):
        console.print(f"[cyan]Extracting subdomains for {domain} from multiple sources...[/cyan]")

        tasks = []

        # Async tasks for API-based sources
        tasks.append(SubdomainRecon.get_crtsh_subdomains(domain))
        tasks.append(SubdomainRecon.get_alienvault_subdomains(domain))
        tasks.append(SubdomainRecon.get_dnsdumpster_subdomains(domain)) # This involves scraping, might be tricky async but we wrap it

        if virustotal_api_key:
            tasks.append(SubdomainRecon.get_virustotal_subdomains(domain, virustotal_api_key))

        # Run external tools in threads to avoid blocking loop
        tasks.append(asyncio.to_thread(SubdomainRecon.run_subfinder, domain))
        tasks.append(asyncio.to_thread(SubdomainRecon.run_sublist3r, domain))

        results = await asyncio.gather(*tasks)

        all_subs = []
        for res in results:
            all_subs.extend(res)

        unique_subs = list(set(all_subs))
        console.print(f"[green]Found {len(unique_subs)} unique subdomains for {domain}[/green]")
        return unique_subs

    @staticmethod
    def run_subfinder(domain):
        """Run subfinder as external tool (sync wrapper)"""
        if not shutil.which('subfinder'):
             return []
        try:
            result = subprocess.run(['subfinder', '-d', domain, '-silent'], capture_output=True, text=True, timeout=60)
            if result.returncode == 0:
                subs = result.stdout.splitlines()
                return list(set(subs))
            return []
        except Exception as e:
            console.print(f"[red]subfinder error: {e}[/red]")
            return []

    @staticmethod
    def run_sublist3r(domain):
        """Run sublist3r if available (sync wrapper)"""
        try:
            import sublist3r
            # Suppress stdout from sublist3r if possible, or just let it run
            subs = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False, enable_bruteforce=False, engines=None)
            return subs if subs else []
        except ImportError:
            return []
        except Exception as e:
            console.print(f"[red]Error extracting subdomains with sublist3r: {e}[/red]")
            return []

    @staticmethod
    async def get_crtsh_subdomains(domain):
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as response:
                    if response.status != 200:
                        return []
                    try:
                        data = await response.json()
                    except:
                        # crt.sh sometimes returns invalid json or html on error
                        return []

                    subs = set()
                    if data and isinstance(data, list):
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            for name in name_value.split('\n'):
                                if domain in name:
                                    subs.add(name.strip())
                    return list(subs)
        except Exception as e:
            console.print(f"[yellow]crt.sh warning: {e}[/yellow]")
            return []

    @staticmethod
    async def get_alienvault_subdomains(domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        subs = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=20) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for record in data.get('passive_dns', []):
                            name = record.get('hostname')
                            if name and domain in name:
                                subs.append(name)
            return list(set(subs))
        except Exception as e:
            console.print(f"[yellow]AlienVault warning: {e}[/yellow]")
            return []

    @staticmethod
    async def get_dnsdumpster_subdomains(domain):
        # DNSDumpster requires CSRF token handling, easier to keep synchronous or wrap in thread.
        # But let's try to do it in thread since it uses requests session logic which is sync.
        return await asyncio.to_thread(SubdomainRecon._get_dnsdumpster_sync, domain)

    @staticmethod
    def _get_dnsdumpster_sync(domain):
        url = 'https://dnsdumpster.com/'
        session = requests.Session()
        subs = []
        try:
            resp = session.get(url, timeout=10)
            soup = BeautifulSoup(resp.text, 'html.parser')
            csrf = soup.find('input', {'name': 'csrfmiddlewaretoken'})
            token = csrf['value'] if csrf else ''
            headers = {'Referer': url, 'User-Agent': 'Mozilla/5.0', 'X-CSRFToken': token}
            data = {'csrfmiddlewaretoken': token, 'targetip': domain}
            post_resp = session.post(url, headers=headers, data=data, timeout=20)
            post_soup = BeautifulSoup(post_resp.text, 'html.parser')
            tables = post_soup.find_all('table')
            for table in tables:
                for row in table.find_all('tr'):
                    cols = row.find_all('td')
                    if len(cols) > 0:
                        sub = cols[0].text.strip()
                        if domain in sub:
                             subs.append(sub)
            return list(set(subs))
        except Exception as e:
            console.print(f"[yellow]DNSDumpster warning: {e}[/yellow]")
            return []

    @staticmethod
    async def get_virustotal_subdomains(domain, api_key):
        if not api_key:
            return []
        url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
        headers = {'x-apikey': api_key}
        subs = []
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=20) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for item in data.get('data', []):
                            subs.append(item['id'])
            return list(set(subs))
        except Exception as e:
            console.print(f"[yellow]VirusTotal warning: {e}[/yellow]")
            return []

    @staticmethod
    def save_domains_to_file(domains, filename):
        unique = sorted(set(domains))
        with open(filename, 'w') as f:
            for d in unique:
                f.write(d + '\n')
        console.print(f"[green]Saved {len(unique)} unique domains to '{filename}'[/green]")
