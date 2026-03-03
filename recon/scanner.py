# recon/scanner.py
import asyncio
import aiohttp
import socket
import dns.resolver
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import ssl
import json
from datetime import datetime
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)


class ReconScanner:
    """Система разведки для сбора информации о цели."""

    def __init__(self, target: str):
        self.target = target
        self.results: Dict[str, any] = {}
        self.start_time = datetime.now()
        self._port_semaphore = asyncio.Semaphore(50)  # ограничение параллельных портов

    async def full_scan(self) -> Dict[str, any]:
        """Полное сканирование цели."""
        logger.info(f"Starting reconnaissance on {self.target}")
        parsed = urlparse(self.target if '://' in self.target else f'http://{self.target}')
        self.results['parsed_url'] = {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'hostname': parsed.hostname,
            'port': parsed.port,
            'path': parsed.path
        }

        await self.resolve_dns()
        await self.scan_ports()
        await self.detect_services()
        await self.ssl_scan()
        await self.find_subdomains()
        await self.check_vulnerabilities()

        self.results['scan_duration'] = (datetime.now() - self.start_time).total_seconds()
        self.results['timestamp'] = datetime.now().isoformat()
        return self.results

    async def resolve_dns(self):
        """Разрешение DNS записей с использованием executor для блокирующих вызовов."""
        logger.info("Resolving DNS records...")
        hostname = self.results['parsed_url']['hostname']
        records = {}
        loop = asyncio.get_event_loop()

        async def resolve_with_executor(query_type):
            try:
                answers = await loop.run_in_executor(
                    None, lambda: dns.resolver.resolve(hostname, query_type)
                )
                return [str(r) for r in answers]
            except Exception:
                return []

        tasks = {
            'A': resolve_with_executor('A'),
            'AAAA': resolve_with_executor('AAAA'),
            'MX': resolve_with_executor('MX'),
            'NS': resolve_with_executor('NS'),
            'TXT': resolve_with_executor('TXT'),
        }

        for qtype, coro in tasks.items():
            records[qtype] = await coro

        self.results['dns_records'] = records
        for rtype, values in records.items():
            if values:
                print(f"{Fore.GREEN}✅ {rtype}: {', '.join(values[:3])}{Style.RESET_ALL}")

    async def scan_ports(self, ports: List[int] = None):
        """Сканирование портов с ограничением параллельности."""
        if not ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                     445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

        hostname = self.results['parsed_url']['hostname']
        open_ports = []
        logger.info(f"Scanning {len(ports)} common ports...")

        async def check_port(port: int) -> Optional[Tuple[int, str]]:
            async with self._port_semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port),
                        timeout=2.0
                    )
                    writer.close()
                    await writer.wait_closed()
                    return (port, "open")
                except (ConnectionRefusedError, asyncio.TimeoutError):
                    return (port, "closed")
                except Exception as e:
                    return (port, f"error: {str(e)}")

        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        for port, status in results:
            if status == "open":
                open_ports.append(port)
                print(f"{Fore.GREEN}✅ Port {port}: OPEN{Style.RESET_ALL}")

        self.results['port_scan'] = {
            'scanned_ports': ports,
            'open_ports': open_ports,
            'total_open': len(open_ports)
        }

    async def detect_services(self):
        """Определение сервисов на открытых портах."""
        if 'port_scan' not in self.results:
            return
        open_ports = self.results['port_scan']['open_ports']
        services = {}
        common_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
            143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
            1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5900: 'VNC',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt'
        }
        for port in open_ports:
            service_name = common_services.get(port, 'unknown')
            banner = await self.get_banner(port)
            if banner:
                service_name = f"{service_name} ({banner[:50]})"
            services[port] = service_name
        self.results['services'] = services

    async def get_banner(self, port: int, timeout: float = 3.0) -> Optional[str]:
        hostname = self.results['parsed_url']['hostname']
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port),
                timeout=timeout
            )
            if port in (80, 8080):
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 22:
                writer.write(b"SSH-2.0-DiamondEye\r\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return None

    async def ssl_scan(self):
        """Сканирование SSL/TLS конфигурации."""
        hostname = self.results['parsed_url']['hostname']
        port = self.results['parsed_url']['port'] or 443
        logger.info("Checking SSL/TLS configuration...")
        ssl_info = {'supported': False, 'certificate': {}, 'protocols': [], 'ciphers': []}
        try:
            for proto in [ssl.PROTOCOL_TLS, ssl.PROTOCOL_TLSv1_2, ssl.PROTOCOL_TLSv1_1]:
                try:
                    context = ssl.SSLContext(proto)
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port, ssl=context),
                        timeout=5.0
                    )
                    ssl_info['supported'] = True
                    ssl_info['protocols'].append(proto.__name__)
                    cert = writer.get_extra_info('ssl_object').getpeercert()
                    if cert:
                        ssl_info['certificate'] = {
                            'issuer': dict(x[0] for x in cert.get('issuer', [])),
                            'subject': dict(x[0] for x in cert.get('subject', [])),
                            'version': cert.get('version'),
                            'notBefore': cert.get('notBefore'),
                            'notAfter': cert.get('notAfter')
                        }
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    continue
        except Exception as e:
            ssl_info['error'] = str(e)
        self.results['ssl_info'] = ssl_info
        if ssl_info['supported']:
            print(f"{Fore.GREEN}✅ SSL/TLS supported{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}⚠️  No SSL/TLS support{Style.RESET_ALL}")

    async def find_subdomains(self, wordlist: List[str] = None):
        """Поиск поддоменов с использованием executor для getaddrinfo."""
        if not wordlist:
            wordlist = ['www', 'mail', 'ftp', 'admin', 'webmail', 'server',
                        'ns1', 'ns2', 'cdn', 'api', 'blog', 'dev', 'test']
        hostname = self.results['parsed_url']['hostname']
        domain_parts = hostname.split('.')
        if len(domain_parts) > 2:
            return
        base_domain = '.'.join(domain_parts[-2:])
        found_subdomains = []
        logger.info("Looking for subdomains...")
        loop = asyncio.get_event_loop()

        async def check_subdomain(sub: str) -> Optional[str]:
            full = f"{sub}.{base_domain}"
            try:
                await loop.run_in_executor(None, socket.gethostbyname, full)
                return full
            except socket.gaierror:
                return None

        tasks = [check_subdomain(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks)
        for sub in results:
            if sub:
                found_subdomains.append(sub)
                print(f"{Fore.GREEN}✅ Found: {sub}{Style.RESET_ALL}")
        self.results['subdomains'] = found_subdomains

    async def check_vulnerabilities(self):
        """Проверка общих уязвимостей."""
        logger.info("Checking for common vulnerabilities...")
        vulnerabilities = []
        hostname = self.results['parsed_url']['hostname']
        scheme = self.results['parsed_url']['scheme'] or 'http'
        base_url = f"{scheme}://{hostname}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.options(base_url, timeout=5) as resp:
                    allowed = resp.headers.get('Allow', '')
                    if 'TRACE' in allowed:
                        vulnerabilities.append({
                            'type': 'HTTP-TRACE', 'severity': 'medium',
                            'description': 'TRACE method enabled (cross-site tracing)'
                        })
        except Exception:
            pass
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{base_url}/phpinfo.php", timeout=5) as resp:
                    if resp.status == 200 and 'phpinfo' in (await resp.text()).lower():
                        vulnerabilities.append({
                            'type': 'PHPINFO', 'severity': 'high',
                            'description': 'phpinfo.php file exposed'
                        })
        except Exception:
            pass
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(base_url, timeout=5) as resp:
                    text = await resp.text()
                    if 'Index of /' in text or 'directory listing' in text.lower():
                        vulnerabilities.append({
                            'type': 'DIRECTORY_LISTING', 'severity': 'low',
                            'description': 'Directory listing enabled'
                        })
        except Exception:
            pass
        self.results['vulnerabilities'] = vulnerabilities
        if vulnerabilities:
            for v in vulnerabilities:
                print(f"{Fore.RED}⚠️  {v['type']}: {v['description']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ No obvious vulnerabilities found{Style.RESET_ALL}")

    def generate_report(self, format: str = 'text') -> str:
        if format == 'json':
            return json.dumps(self.results, indent=2, default=str)
        report = []
        report.append("=" * 60)
        report.append(f"RECONNAISSANCE REPORT - {self.target}")
        report.append("=" * 60)
        report.append(f"Scan time: {self.results.get('timestamp', 'N/A')}")
        report.append(f"Duration: {self.results.get('scan_duration', 0):.2f}s")
        report.append("")
        report.append("[DNS Records]")
        for rtype, vals in self.results.get('dns_records', {}).items():
            if vals:
                report.append(f"  {rtype}: {', '.join(vals)}")
        if 'port_scan' in self.results:
            report.append("")
            report.append("[Open Ports]")
            for port in self.results['port_scan']['open_ports']:
                service = self.results.get('services', {}).get(port, 'unknown')
                report.append(f"  {port}: {service}")
        if 'vulnerabilities' in self.results and self.results['vulnerabilities']:
            report.append("")
            report.append("[Vulnerabilities Found]")
            for v in self.results['vulnerabilities']:
                report.append(f"  {v['type']} ({v['severity']}): {v['description']}")
        report.append("")
        report.append("=" * 60)
        return '\n'.join(report)


async def quick_recon(target: str) -> Dict[str, any]:
    scanner = ReconScanner(target)
    results = await scanner.full_scan()
    print("\n" + scanner.generate_report())
    filename = f"recon_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n{Fore.GREEN}✅ Report saved to {filename}{Style.RESET_ALL}")
    return results