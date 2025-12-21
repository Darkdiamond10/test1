import ssl
import socket
import asyncio
import aiohttp
import requests
import time
from .utils import console, TargetUtils, G, R, C, YELLOW, MAGENTA, RESET

class NetworkScanner:
    # Legacy synchronous methods (kept for backward compatibility or single target use if needed,
    # though we will shift to async)
    @staticmethod
    def scan_sni(domain, port, timeout=3):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = cert.get('issuer')
                    issuer_str = str(issuer)
                    return (True, f"Handshake success | Issuer: {issuer_str}")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_ssl(domain, port, timeout=3):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, port), timeout=timeout) as sock:
                 with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    return (True, "SSL connection success")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_proxy(domain, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((domain, port))
            connect_req = f"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com\r\n\r\n"
            sock.send(connect_req.encode())
            resp = sock.recv(1024).decode(errors='ignore')
            sock.close()
            if '200 Connection established' in resp or 'HTTP/1.1 200' in resp:
                return (True, 'Proxy OK')
            return (False, 'Proxy connection failed')
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_http(domain, port, timeout=3):
        try:
            url = f"http://{domain}:{port}"
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            server = resp.headers.get('Server', 'Unknown')
            if resp.status_code == 302:
                return (False, f"Redirect 302 ignored | Server: {server}")
            return (True, f"{resp.status_code} OK | Server: {server}")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_https(domain, port, timeout=3):
        try:
            url = f"https://{domain}:{port}"
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            server = resp.headers.get('Server', 'Unknown')
            if resp.status_code == 302:
                return (False, f"Redirect 302 ignored | Server: {server}")
            return (True, f"{resp.status_code} OK | Server: {server}")
        except Exception as e:
            return (False, str(e))


class AsyncNetworkScanner:
    def __init__(self, mode, port, concurrency, output_file):
        self.mode = mode
        self.port = port
        self.concurrency = concurrency
        self.output_file = output_file
        self.total = 0
        self.progress = 0
        self.start_time = time.time()

    def _append_to_file(self, content):
        with open(self.output_file, 'a') as f:
            f.write(content)

    async def check_sni(self, domain, port, timeout=3):
        try:
            # Equivalent to ssl.create_default_context()
            context = ssl.create_default_context()
            # In asyncio, we use open_connection with ssl argument
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port, ssl=context, server_hostname=domain),
                timeout=timeout
            )
            # Get certificate
            sock = writer.get_extra_info('ssl_object')
            if sock:
                cert = sock.getpeercert()
                issuer = cert.get('issuer')
                issuer_str = str(issuer)
                writer.close()
                await writer.wait_closed()
                return (True, f"Handshake success | Issuer: {issuer_str}")

            writer.close()
            await writer.wait_closed()
            return (False, "No SSL object")
        except Exception as e:
            return (False, str(e))

    async def check_ssl(self, domain, port, timeout=3):
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port, ssl=context, server_hostname=domain),
                timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return (True, "SSL connection success")
        except Exception as e:
            return (False, str(e))

    async def check_proxy(self, domain, port, timeout=3):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(domain, port),
                timeout=timeout
            )
            connect_req = f"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com\r\n\r\n"
            writer.write(connect_req.encode())
            await writer.drain()

            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            resp = data.decode(errors='ignore')

            writer.close()
            await writer.wait_closed()

            if '200 Connection established' in resp or 'HTTP/1.1 200' in resp:
                return (True, 'Proxy OK')
            return (False, 'Proxy connection failed')
        except Exception as e:
            return (False, str(e))

    async def check_http(self, session, domain, port, timeout=3):
        try:
            url = f"http://{domain}:{port}"
            async with session.get(url, timeout=timeout, allow_redirects=False) as r:
                server = r.headers.get('Server', 'Unknown')
                if r.status == 302:
                    return (False, f"Redirect 302 ignored | Server: {server}")
                return (True, f"{r.status} OK | Server: {server}")
        except Exception as e:
            return (False, str(e))

    async def check_https(self, session, domain, port, timeout=3):
        try:
            url = f"https://{domain}:{port}"
            async with session.get(url, timeout=timeout, ssl=False, allow_redirects=False) as r:
                server = r.headers.get('Server', 'Unknown')
                if r.status == 302:
                    return (False, f"Redirect 302 ignored | Server: {server}")
                return (True, f"{r.status} OK | Server: {server}")
        except Exception as e:
            return (False, str(e))

    async def worker(self, session, queue):
        while True:
            target = await queue.get()
            try:
                result = (False, "")

                # Check mode and call appropriate async function
                if self.mode == '1': # SNI
                    result = await self.check_sni(target, self.port)
                elif self.mode == '2': # SSL
                    result = await self.check_ssl(target, self.port)
                elif self.mode == '3': # Proxy
                    result = await self.check_proxy(target, self.port)
                elif self.mode == '4': # HTTP
                    result = await self.check_http(session, target, self.port)
                elif self.mode == '5': # HTTPS
                    result = await self.check_https(session, target, self.port)

                # Progress Update
                self.progress += 1

                if result[0]:
                    # Positive result
                    console.print(f"{G}[{self.progress}/{self.total}] {target} | {result[1]}{RESET}")
                    if self.output_file:
                        loop = asyncio.get_event_loop()
                        await loop.run_in_executor(None, self._append_to_file, f"{target}:{self.port}\n")
                else:
                    # Negative result (can be verbose or quiet, usually quiet for bulk scan to avoid spam)
                    # For now, let's print errors in RED but maybe simpler
                     console.print(f"{R}[{self.progress}/{self.total}] {target} | {result[1]}{RESET}")

            except Exception as main_e:
                console.print(f"{R}[!] Error scanning {target}: {main_e}{RESET}")
            finally:
                queue.task_done()

    async def start_scan(self, targets_input):
        console.print(f"{YELLOW}→ Preparing bulk scan ({self.mode}) with limit {self.concurrency}...{RESET}")

        self.total = TargetUtils.count_targets(targets_input)
        queue = asyncio.Queue(maxsize=self.concurrency * 2)

        # Determine if we need a session (HTTP/S) or not (Raw Sockets)
        # We'll create one anyway for HTTP modes, it's cheap
        connector = aiohttp.TCPConnector(ssl=False, limit=self.concurrency)
        async with aiohttp.ClientSession(connector=connector) as session:
            workers = [asyncio.create_task(self.worker(session, queue)) for _ in range(self.concurrency)]

            for target in TargetUtils.generate_targets(targets_input):
                await queue.put(target)

            await queue.join()

            for w in workers:
                w.cancel()

        duration = int(time.time() - self.start_time)
        console.print(f"\n{MAGENTA}[✓] Scan finished in {duration}s. Total Targets: {self.total}{RESET}")

    def run_bulk(self, targets_input):
        asyncio.run(self.start_scan(targets_input))            sock.connect((domain, port))
            connect_req = f"CONNECT google.com:443 HTTP/1.1\r\nHost: google.com\r\n\r\n"
            sock.send(connect_req.encode())
            resp = sock.recv(1024).decode(errors='ignore')
            sock.close()
            if '200 Connection established' in resp or 'HTTP/1.1 200' in resp:
                return (True, 'Proxy OK')
            return (False, 'Proxy connection failed')
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_http(domain, port, timeout=3):
        try:
            url = f"http://{domain}:{port}"
            resp = requests.get(url, timeout=timeout, allow_redirects=False)
            server = resp.headers.get('Server', 'Unknown')
            if resp.status_code == 302:
                return (False, f"Redirect 302 ignored | Server: {server}")
            return (True, f"{resp.status_code} OK | Server: {server}")
        except Exception as e:
            return (False, str(e))

    @staticmethod
    def scan_https(domain, port, timeout=3):
        try:
            url = f"https://{domain}:{port}"
            resp = requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
            server = resp.headers.get('Server', 'Unknown')
            if resp.status_code == 302:
                return (False, f"Redirect 302 ignored | Server: {server}")
            return (True, f"{resp.status_code} OK | Server: {server}")
        except Exception as e:
            return (False, str(e))
