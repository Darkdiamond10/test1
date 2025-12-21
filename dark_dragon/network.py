import ssl
import socket
import requests
from .utils import console

class NetworkScanner:
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
