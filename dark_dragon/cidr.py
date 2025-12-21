import asyncio
import aiohttp
import time
from .utils import console, G, R, C, YELLOW, MAGENTA, RESET, TargetUtils

class CIDRScanner:
    def __init__(self, port, concurrency, output_file):
        self.port = port
        self.concurrency = concurrency
        self.output_file = output_file
        self.total = 0
        self.progress = 0
        self.start_time = time.time()
        self.cdn_keywords = ['cloudflare', 'cloudfront', 'akamai', 'google', 'fastly', 'openresty', 'tengine', 'varnish', 'google frontend', 'googlefrontend']

    async def check_ip(self, session, ip):
        url = f"https://{ip}" if self.port == 443 else f"http://{ip}:{self.port}"
        status = 0
        server = 'no-response'
        cf_ray = '-'

        try:
            async with session.get(url, timeout=1.5, allow_redirects=False, ssl=False) as r:
                status = r.status
                server = r.headers.get('server', 'unknown').lower()
                cf_ray = r.headers.get('cf-ray', '-')
        except:
            pass

        # Update progress
        self.progress += 1

        # Logic from original script: Ignore 302/307
        if status in (302, 307):
            console.print(f"{YELLOW}[{self.progress}/{self.total}] {ip:<15} | {status:<3} | {server:<20} | CF-RAY: {cf_ray} [IGNORED]{RESET}")
            return

        is_cdn = any(cdn in server for cdn in self.cdn_keywords)
        valid_codes = [200, 201, 202, 204, 206, 300, 301, 303, 304, 400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504]

        if status in valid_codes:
            result_line = f"{ip}\t{status}\t{server}\tCF-RAY: {cf_ray}\n"
            with open(self.output_file, 'a') as f:
                f.write(result_line)

        # Output to screen
        color = G if is_cdn else (C if status != 0 else R)
        console.print(f"{color}[{self.progress}/{self.total}] {ip:<15} | {status:<3} | {server:<20} | CF-RAY: {cf_ray}{RESET}")

    async def worker(self, session, queue):
        while True:
            ip = await queue.get()
            try:
                await self.check_ip(session, ip)
            finally:
                queue.task_done()

    async def start_scan(self, ranges_input):
        console.print(f"{YELLOW}→ Preparing scan with limit {self.concurrency} on port {self.port}...{RESET}")

        self.total = TargetUtils.count_targets(ranges_input)
        queue = asyncio.Queue(maxsize=self.concurrency * 2)

        # Create a single session for all requests
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            # Start workers
            workers = [asyncio.create_task(self.worker(session, queue)) for _ in range(self.concurrency)]

            # Feed the queue
            for ip in TargetUtils.generate_targets(ranges_input):
                await queue.put(ip)

            # Wait for queue to be empty
            await queue.join()

            # Cancel workers
            for w in workers:
                w.cancel()

        duration = int(time.time() - self.start_time)
        console.print(f"\n{MAGENTA}[✓] Scan finished in {duration}s. Total IPs: {self.total}{RESET}")

    def run(self, ranges_input):
        """Entry point to run async scan from sync context"""
        asyncio.run(self.start_scan(ranges_input))
