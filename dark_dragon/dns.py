import asyncio
import aiodns
import time
from .utils import console, TargetUtils

class DNSScanner:
    def __init__(self, concurrency=50, output_file='valid_dns.txt', timeout=3.0):
        self.concurrency = concurrency
        self.output_file = output_file
        self.timeout = timeout
        self.total = 0
        self.progress = 0
        self.start_time = time.time()
        with open(self.output_file, 'w') as f:
            pass

    async def check_ip(self, ip):
        try:
            resolver = aiodns.DNSResolver(timeout=self.timeout, tries=1)
            resolver.nameservers = [ip]
            await resolver.query('google.com', 'A')

            with open(self.output_file, 'a') as f:
                f.write(f"{ip}\n")

            console.print(f"[green][+] {ip} is a valid DNS resolver[/green]")
            return True
        except Exception:
            pass
        finally:
            self.progress += 1

    async def worker(self, queue):
        while True:
            ip = await queue.get()
            try:
                await self.check_ip(ip)
            finally:
                queue.task_done()

    async def producer(self, queue, ranges_input):
        """Produces IPs into the queue."""
        for ip in TargetUtils.generate_targets(ranges_input):
            await queue.put(ip)

    async def start_scan(self, ranges_input):
        console.print(f"[yellow]→ Preparing DNS scan with limit {self.concurrency}...[/yellow]")

        self.total = TargetUtils.count_targets(ranges_input)
        console.print(f"[cyan]Total targets: {self.total}[/cyan]")

        # Bounded queue to prevent memory issues
        queue = asyncio.Queue(maxsize=self.concurrency * 2)

        # Start workers
        workers = [asyncio.create_task(self.worker(queue)) for _ in range(self.concurrency)]

        # Start producer
        producer_task = asyncio.create_task(self.producer(queue, ranges_input))

        # Wait for producer to finish
        await producer_task

        # Wait for queue to be fully processed
        await queue.join()

        # Cancel workers
        for w in workers:
            w.cancel()

        duration = int(time.time() - self.start_time)
        console.print(f"\n[magenta][✓] Scan finished in {duration}s. Valid IPs saved to {self.output_file}[/magenta]")

    def run(self, ranges_input):
        """Entry point to run async scan from sync context"""
        asyncio.run(self.start_scan(ranges_input))
