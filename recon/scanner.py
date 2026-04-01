# recon/scanner.py
import asyncio
import aiohttp
import socket
import dns.resolver
import dns.exception
import ssl
import json
import re
import os
from typing import Dict, List, Optional, Tuple, Set, Any
from urllib.parse import urlparse, urljoin
from datetime import datetime
import logging
from dataclasses import dataclass, field
import ipaddress

from colorama import Fore, Style
from utils import load_wordlist_paths, load_subdomains_list, load_useragents_from_file

# Import optional modules
from bypass.waf_detector import WAFDetector, WAFType
from recon.wayback import WaybackMachine
from recon.crt import CertificateTransparency

try:
    from recon.syn_scanner import SynScanner
    SYN_SCAN_AVAILABLE = True
except ImportError:
    SYN_SCAN_AVAILABLE = False

logger = logging.getLogger(__name__)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class ServiceInfo:
    port: int
    service: str
    banner: Optional[str] = None
    ssl: bool = False
    http_title: Optional[str] = None
    http_server: Optional[str] = None


@dataclass
class DNSRecord:
    type: str
    value: str
    ttl: int = 0


class ReconScanner:
    def __init__(self, target: str, timeout: float = 3.0, max_concurrent: int = 100):
        self.target = self._normalize_target(target)
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.all_ports = False
        self.custom_ports = None
        self._stop_scan = False
        self._use_syn_scan = False
        self._fetch_wayback = False
        self._fetch_crt = False
        
        self.COMMON_SERVICES = self._load_common_services()
        self.SENSITIVE_FILES = self._load_sensitive_files()
        
        self.results: Dict[str, Any] = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'dns_records': {},
            'ports': [],
            'services': {},
            'ssl': {},
            'subdomains': [],
            'vulnerabilities': [],
            'technologies': [],
            'sensitive_files': [],
            'waf': None,
            'wayback_urls': [],
        }
        
        self.start_time = datetime.now()
        self._dns_resolver = dns.resolver.Resolver()
        self._dns_resolver.timeout = timeout
        self._dns_resolver.lifetime = timeout
        self._dns_cache: Dict[str, List[DNSRecord]] = {}
    
    def _load_common_services(self) -> Dict[int, str]:
        services = {}
        services_file = os.path.join(ROOT_DIR, "wordlists", "services.txt")
        try:
            with open(services_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        port_str, service = line.split(':', 1)
                        try:
                            port = int(port_str)
                            services[port] = service
                        except ValueError:
                            pass
        except Exception as e:
            logger.warning(f"Failed to load services: {e}")
        
        if not services:
            services = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
                143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 993: 'IMAPS',
                995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
                5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
                27017: 'MongoDB', 9200: 'Elasticsearch'
            }
        return services

    def _load_sensitive_files(self) -> List[str]:
        files = []
        files_file = os.path.join(ROOT_DIR, "wordlists", "sensitive_files.txt")
        try:
            with open(files_file, 'r') as f:
                files = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.warning(f"Failed to load sensitive files: {e}")
        if not files:
            files = [
                '/.git/HEAD', '/.env', '/.htaccess', '/.htpasswd',
                '/wp-config.php', '/config.php', '/configuration.php',
                '/phpinfo.php', '/info.php', '/test.php',
                '/backup.sql', '/dump.sql', '/db.sql',
                '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
                '/server-status', '/server-info', '/phpmyadmin/',
                '/web.config', '/.well-known/security.txt',
                '/.aws/credentials', '/.azure/accessTokens.json', '/.gcloud/credentials'
            ]
        return files
    
    def _normalize_target(self, target: str) -> str:
        target = target.strip().lower()
        if '://' in target:
            target = target.split('://', 1)[1]
        target = target.split('/')[0]
        target = target.split(':')[0]
        return target
    
    async def fetch_wayback_urls(self):
        """Fetch historical URLs from Wayback Machine."""
        try:
            wb = WaybackMachine(self.target)
            urls = await wb.fetch_urls()
            self.results['wayback_urls'] = list(urls)
            print(f"{Fore.CYAN}📜 Wayback Machine: {len(urls)} historical URLs{Style.RESET_ALL}")
            await wb.close()
        except Exception as e:
            logger.debug(f"Wayback fetch failed: {e}")
            self.results['wayback_urls'] = []
    
    async def fetch_crt_subdomains(self):
        """Fetch subdomains from certificate logs."""
        try:
            crt = CertificateTransparency(self.target)
            subdomains = await crt.fetch_subdomains()
            existing = {s['subdomain'] for s in self.results.get('subdomains', []) if isinstance(s, dict)}
            new_subs = []
            for s in subdomains:
                if s not in existing:
                    new_subs.append({'subdomain': s, 'source': 'crt.sh'})
                    existing.add(s)
            self.results['subdomains'].extend(new_subs)
            print(f"{Fore.CYAN}🔐 CRT.sh: {len(new_subs)} new subdomains{Style.RESET_ALL}")
            await crt.close()
        except Exception as e:
            logger.debug(f"CRT fetch failed: {e}")
    
    async def detect_waf(self):
        """Detect WAF from HTTP response."""
        try:
            async with aiohttp.ClientSession() as session:
                for port in [80, 443, 8080, 8443]:
                    if port in self.results['ports']:
                        scheme = 'https' if port in (443, 8443) else 'http'
                        url = f"{scheme}://{self.target}:{port}"
                        async with session.get(url, timeout=5, ssl=False) as resp:
                            headers = dict(resp.headers)
                            waf_type = WAFDetector.detect(headers)
                            if waf_type != WAFType.UNKNOWN:
                                self.results['waf'] = waf_type.value
                                print(f"{Fore.GREEN}✅ Detected WAF: {waf_type.value.upper()}{Style.RESET_ALL}")
                                break
        except Exception as e:
            logger.debug(f"WAF detection failed: {e}")
    
    async def full_scan(self) -> Dict[str, Any]:
        try:
            logger.info(f"Starting reconnaissance on {self.target}")
            
            parsed = urlparse(self.target if '://' in self.target else f'http://{self.target}')
            self.results['parsed_url'] = {
                'scheme': parsed.scheme,
                'netloc': parsed.netloc,
                'hostname': parsed.hostname,
                'port': parsed.port,
                'path': parsed.path
            }
            
            tasks = [
                self.resolve_dns(),
                self.scan_ports(),
                self.find_subdomains(),
                self.scan_sensitive_files(),
                self.detect_technologies(),
                self.check_vulnerabilities(),
                self.detect_waf(),
            ]
            
            if self._fetch_wayback:
                tasks.append(self.fetch_wayback_urls())
            if self._fetch_crt:
                tasks.append(self.fetch_crt_subdomains())
            
            await asyncio.gather(*tasks, return_exceptions=True)
            
            await self.detect_services()
            await self.ssl_scan()
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️ Scan interrupted by user{Style.RESET_ALL}")
            self._stop_scan = True
        
        self.results['scan_duration'] = (datetime.now() - self.start_time).total_seconds()
        return self.results
    
    async def resolve_dns(self):
        logger.info("Resolving DNS records...")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
        records = {}
        
        for qtype in record_types:
            if self._stop_scan:
                break
            try:
                answers = await self._resolve_dns_type(self.target, qtype)
                if answers:
                    records[qtype] = answers
                    for ans in answers[:3]:
                        print(f"{Fore.GREEN}✅ {qtype}: {ans}{Style.RESET_ALL}")
            except dns.exception.DNSException:
                pass
            except Exception as e:
                logger.debug(f"DNS {qtype} error: {e}")
        
        self.results['dns_records'] = records
    
    async def _resolve_dns_type(self, hostname: str, qtype: str) -> List[str]:
        cache_key = f"{hostname}:{qtype}"
        if cache_key in self._dns_cache:
            return [r.value for r in self._dns_cache[cache_key]]
        
        try:
            answers = await asyncio.get_event_loop().run_in_executor(
                None, 
                lambda: self._dns_resolver.resolve(hostname, qtype)
            )
            values = []
            for answer in answers:
                if qtype == 'MX':
                    value = f"{answer.exchange} (priority {answer.preference})"
                else:
                    value = str(answer)
                values.append(value)
            
            self._dns_cache[cache_key] = [
                DNSRecord(type=qtype, value=v, ttl=answers.rrset.ttl) for v in values
            ]
            return values
        except dns.exception.DNSException:
            return []
    
    async def scan_ports_syn(self, ports: List[int]) -> List[ServiceInfo]:
        """Fast SYN port scan."""
        if not SYN_SCAN_AVAILABLE:
            logger.warning("SYN scan not available")
            return []
        
        print(f"{Fore.CYAN}⚡ Using SYN scan for {len(ports)} ports...{Style.RESET_ALL}")
        
        scanner = SynScanner(self.target, concurrency=self.max_concurrent)
        results = await scanner.scan(ports)
        
        open_ports = []
        for r in results:
            if r.state == "open":
                service = self.COMMON_SERVICES.get(r.port, 'unknown')
                open_ports.append(ServiceInfo(port=r.port, service=service))
                print(f"{Fore.GREEN}✅ Port {r.port}: {service} - OPEN{Style.RESET_ALL}")
        
        return open_ports
    
    async def scan_ports(self):
        if self.all_ports:
            ports = list(range(1, 65536))
            logger.info(f"🔥 Scanning all 65535 ports...")
            print(f"{Fore.YELLOW}⚠️ Full port scan may take time. Press Ctrl+C to stop.{Style.RESET_ALL}")
            concurrency = self.max_concurrent
            show_progress = True
        elif self.custom_ports:
            ports = self.custom_ports
            logger.info(f"Scanning {len(ports)} custom ports...")
            concurrency = self.max_concurrent
            show_progress = False
        else:
            ports = list(self.COMMON_SERVICES.keys())
            logger.info(f"Scanning {len(ports)} common ports...")
            concurrency = self.max_concurrent
            show_progress = False
        
        hostname = self.results['parsed_url']['hostname']
        open_ports = []
        
        if self._use_syn_scan and SYN_SCAN_AVAILABLE:
            import os
            if os.geteuid() == 0:
                results = await self.scan_ports_syn(ports)
                for r in results:
                    open_ports.append(r)
                    self.results['ports'].append(r.port)
                    self.results['services'][r.port] = r
                logger.info(f"Found {len(open_ports)} open ports (SYN scan)")
                return
        
        semaphore = asyncio.Semaphore(concurrency)
        scanned = 0
        total = len(ports)
        
        async def check_port(port: int) -> Optional[ServiceInfo]:
            nonlocal scanned
            async with semaphore:
                if self._stop_scan:
                    return None
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port),
                        timeout=1.0 if self.all_ports else self.timeout
                    )
                    service = self.COMMON_SERVICES.get(port, 'unknown')
                    banner = await self._get_banner(reader, writer, port)
                    writer.close()
                    await writer.wait_closed()
                    
                    scanned += 1
                    if show_progress and scanned % 1000 == 0:
                        print(f"{Fore.CYAN}📡 Progress: {scanned}/{total} ports scanned ({scanned/total*100:.1f}%){Style.RESET_ALL}")
                    
                    return ServiceInfo(port=port, service=service, banner=banner)
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    scanned += 1
                    return None
                except Exception as e:
                    logger.debug(f"Port {port} scan error: {e}")
                    scanned += 1
                    return None
        
        tasks = [check_port(p) for p in ports]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if result:
                open_ports.append(result)
                self.results['ports'].append(result.port)
                self.results['services'][result.port] = result
                print(f"{Fore.GREEN}✅ Port {result.port}: {result.service} - OPEN{Style.RESET_ALL}")
        
        logger.info(f"Found {len(open_ports)} open ports")
    
    async def _get_banner(self, reader, writer, port: int) -> Optional[str]:
        try:
            if port in (80, 8080, 443, 8443):
                writer.write(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            elif port == 22:
                writer.write(b"SSH-2.0-OpenSSH_Test\r\n")
            elif port == 21:
                writer.write(b"USER anonymous\r\n")
            elif port == 25:
                writer.write(b"EHLO test.local\r\n")
            else:
                writer.write(b"\r\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            if banner:
                return banner.decode('utf-8', errors='ignore').strip()[:200]
        except (asyncio.TimeoutError, ConnectionError, OSError):
            pass
        except Exception:
            pass
        return None
    
    async def detect_services(self):
        for port_info in self.results['services'].values():
            if port_info.service in ('HTTP', 'HTTPS', 'HTTP-Proxy', 'HTTPS-Alt'):
                await self._http_service_detect(port_info)
    
    async def _http_service_detect(self, service_info: ServiceInfo):
        scheme = 'https' if service_info.port in (443, 8443) else 'http'
        url = f"{scheme}://{self.target}:{service_info.port}"
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=self.timeout, ssl=False) as resp:
                    if 'Server' in resp.headers:
                        service_info.http_server = resp.headers['Server']
                        service_info.service += f" ({service_info.http_server})"
                    text = await resp.text()
                    title_match = re.search(r'<title>(.*?)</title>', text, re.IGNORECASE)
                    if title_match:
                        service_info.http_title = title_match.group(1).strip()
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        except Exception:
            pass
    
    async def ssl_scan(self):
        ssl_ports = [p for p in self.results['ports'] if p in (443, 8443, 465, 993, 995)]
        
        for port in ssl_ports:
            if self._stop_scan:
                break
            ssl_info = await self._check_ssl(self.target, port)
            if ssl_info:
                self.results['ssl'][port] = ssl_info
                print(f"{Fore.GREEN}✅ SSL/TLS on port {port}{Style.RESET_ALL}")
    
    async def _check_ssl(self, hostname: str, port: int) -> Optional[Dict]:
        ssl_info = {'supported': False, 'certificate': {}, 'protocols': [], 'weak': []}
        
        try:
            context = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=context),
                timeout=self.timeout
            )
            ssl_info['supported'] = True
            ssl_info['protocols'].append('TLSv1.2+')
            
            ssl_obj = writer.get_extra_info('ssl_object')
            cert = ssl_obj.getpeercert()
            if cert:
                ssl_info['certificate'] = {
                    'issuer': dict(x[0] for x in cert.get('issuer', [])),
                    'subject': dict(x[0] for x in cert.get('subject', [])),
                    'notAfter': cert.get('notAfter'),
                }
            writer.close()
            await writer.wait_closed()
        except (asyncio.TimeoutError, ssl.SSLError, ConnectionError):
            pass
        except Exception:
            pass
        
        return ssl_info if ssl_info['supported'] else None
    
    async def find_subdomains(self):
        try:
            ipaddress.ip_address(self.target)
            return
        except ValueError:
            pass
        
        sub_list = load_subdomains_list()
        
        found = []
        semaphore = asyncio.Semaphore(100)
        
        async def check_sub(sub: str) -> Optional[Dict]:
            async with semaphore:
                if self._stop_scan:
                    return None
                full = f"{sub}.{self.target}"
                try:
                    ip = await asyncio.get_event_loop().run_in_executor(
                        None, socket.gethostbyname, full
                    )
                    return {'subdomain': full, 'ip': ip}
                except (socket.gaierror, OSError):
                    return None
                except Exception:
                    return None
        
        tasks = [check_sub(sub) for sub in sub_list[:500]]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                found.append(res)
                print(f"{Fore.GREEN}✅ Found: {res['subdomain']} -> {res['ip']}{Style.RESET_ALL}")
        
        self.results['subdomains'].extend(found)
    
    async def scan_sensitive_files(self):
        found = []
        base_url = f"http://{self.target}"
        
        async def check_file(path: str) -> Optional[Dict]:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(base_url + path, timeout=3) as resp:
                        if resp.status == 200:
                            size = len(await resp.read())
                            return {'path': path, 'status': resp.status, 'size': size}
                        elif resp.status in [401, 403]:
                            return {'path': path, 'status': resp.status, 'protected': True}
            except (aiohttp.ClientError, asyncio.TimeoutError):
                pass
            except Exception:
                pass
            return None
        
        tasks = [check_file(path) for path in self.SENSITIVE_FILES]
        results = await asyncio.gather(*tasks)
        
        for res in results:
            if res:
                found.append(res)
                status_color = Fore.RED if res['status'] == 200 else Fore.YELLOW
                print(f"{status_color}🔓 Found: {res['path']} ({res['status']}){Style.RESET_ALL}")
        
        self.results['sensitive_files'] = found
    
    async def detect_technologies(self):
        tech = set()
        
        for service in self.results['services'].values():
            banner = (service.banner or '').lower()
            if 'nginx' in banner:
                tech.add('nginx')
            if 'apache' in banner:
                tech.add('apache')
            if 'iis' in banner:
                tech.add('IIS')
            if 'php' in banner:
                tech.add('PHP')
            if 'python' in banner:
                tech.add('Python')
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{self.target}") as resp:
                    cookies = resp.headers.get('Set-Cookie', '')
                    if 'PHPSESSID' in cookies:
                        tech.add('PHP')
                    if 'JSESSIONID' in cookies:
                        tech.add('Java/JSP')
                    if 'ASP.NET' in cookies:
                        tech.add('ASP.NET')
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
        except Exception:
            pass
        
        self.results['technologies'] = list(tech)
        if tech:
            print(f"{Fore.CYAN}🔧 Technologies: {', '.join(tech)}{Style.RESET_ALL}")
    
    async def check_vulnerabilities(self):
        vulns = []
        
        for port_info in self.results['services'].values():
            if port_info.port in (21, 23):
                vulns.append({
                    'type': 'Insecure Protocol',
                    'port': port_info.port,
                    'severity': 'medium',
                    'description': f'{port_info.service} is unencrypted'
                })
            if port_info.port in (3306, 5432, 27017, 6379):
                vulns.append({
                    'type': 'Database Exposure',
                    'port': port_info.port,
                    'severity': 'high',
                    'description': f'{port_info.service} exposed to internet'
                })
        
        self.results['vulnerabilities'] = vulns
        if vulns:
            print(f"{Fore.RED}🔴 Found {len(vulns)} potential vulnerabilities{Style.RESET_ALL}")
    
    def generate_report(self, format: str = 'text') -> str:
        if format == 'json':
            return json.dumps(self.results, indent=2, default=str, ensure_ascii=False)
        
        report = []
        report.append("=" * 60)
        report.append(f"RECONNAISSANCE REPORT - {self.target}")
        report.append("=" * 60)
        report.append(f"Scan time: {self.results['timestamp']}")
        report.append(f"Duration: {self.results.get('scan_duration', 0):.2f}s")
        report.append("")
        
        if self.results['waf']:
            report.append(f"[WAF] Detected: {self.results['waf'].upper()}")
            report.append("")
        
        if self.results['dns_records']:
            report.append("[DNS Records]")
            for rtype, values in self.results['dns_records'].items():
                if values:
                    report.append(f"  {rtype}: {', '.join(values)}")
        
        if self.results['ports']:
            report.append("\n[Open Ports]")
            for port in sorted(self.results['ports']):
                service = self.results['services'].get(port)
                if service:
                    banner = f" - {service.banner}" if service.banner else ""
                    title = f" [{service.http_title}]" if service.http_title else ""
                    report.append(f"  {port}: {service.service}{banner}{title}")
        
        if self.results['subdomains']:
            report.append("\n[Subdomains]")
            for sub in self.results['subdomains']:
                if isinstance(sub, dict):
                    report.append(f"  {sub['subdomain']} -> {sub.get('ip', '?')} [{sub.get('source', 'dns')}]")
                else:
                    report.append(f"  {sub}")
        
        if self.results['wayback_urls']:
            report.append(f"\n[Wayback Machine] {len(self.results['wayback_urls'])} URLs")
            for url in list(self.results['wayback_urls'])[:20]:
                report.append(f"  {url}")
            if len(self.results['wayback_urls']) > 20:
                report.append(f"  ... and {len(self.results['wayback_urls']) - 20} more")
        
        if self.results['sensitive_files']:
            report.append("\n[Sensitive Files]")
            for f in self.results['sensitive_files']:
                report.append(f"  {f['path']} ({f['status']})")
        
        if self.results['technologies']:
            report.append("\n[Technologies]")
            for tech in sorted(self.results['technologies']):
                report.append(f"  {tech}")
        
        if self.results['vulnerabilities']:
            report.append("\n[Vulnerabilities]")
            for v in self.results['vulnerabilities']:
                report.append(f"  {v['type']} ({v['severity']}): {v.get('description', '')}")
        
        report.append("")
        report.append("=" * 60)
        return '\n'.join(report)


async def quick_recon(target: str, all_ports: bool = False, ports_list: Optional[List[int]] = None,
                      wayback: bool = False, crt: bool = False, syn_scan: bool = False) -> Dict[str, Any]:
    """
    Быстрая разведка цели.
    """
    scanner = ReconScanner(target)
    scanner.all_ports = all_ports
    scanner.custom_ports = ports_list
    scanner._fetch_wayback = wayback
    scanner._fetch_crt = crt
    scanner._use_syn_scan = syn_scan
    
    if syn_scan:
        import os
        if os.geteuid() != 0:
            print(f"{Fore.YELLOW}⚠️ SYN scan requires root privileges. Falling back to TCP connect.{Style.RESET_ALL}")
            scanner._use_syn_scan = False
    
    results = await scanner.full_scan()
    print("\n" + scanner.generate_report())
    return results