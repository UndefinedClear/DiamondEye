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
from colorama import Fore, Style


class ReconScanner:
    """Система разведки для сбора информации о цели"""
    
    def __init__(self, target: str):
        self.target = target
        self.results: Dict[str, any] = {}
        self.start_time = datetime.now()
        
    async def full_scan(self) -> Dict[str, any]:
        """Полное сканирование цели"""
        print(f"{Fore.CYAN}🎯 Starting reconnaissance on {self.target}{Style.RESET_ALL}")
        
        # Парсинг URL
        parsed = urlparse(self.target if '://' in self.target else f'http://{self.target}')
        self.results['parsed_url'] = {
            'scheme': parsed.scheme,
            'netloc': parsed.netloc,
            'hostname': parsed.hostname,
            'port': parsed.port,
            'path': parsed.path
        }
        
        # Получение IP адресов
        await self.resolve_dns()
        
        # Сканирование портов
        await self.scan_ports()
        
        # Проверка сервисов
        await self.detect_services()
        
        # Сбор информации о SSL/TLS
        await self.ssl_scan()
        
        # Поиск поддоменов
        await self.find_subdomains()
        
        # Проверка уязвимостей
        await self.check_vulnerabilities()
        
        # Генерация отчета
        self.results['scan_duration'] = (datetime.now() - self.start_time).total_seconds()
        self.results['timestamp'] = datetime.now().isoformat()
        
        return self.results
    
    async def resolve_dns(self):
        """Разрешение DNS записей"""
        print(f"{Fore.CYAN}🔍 Resolving DNS records...{Style.RESET_ALL}")
        
        hostname = self.results['parsed_url']['hostname']
        records = {}
        
        try:
            # A records
            answers = dns.resolver.resolve(hostname, 'A')
            records['A'] = [str(r) for r in answers]
        except:
            records['A'] = []
        
        try:
            # AAAA records (IPv6)
            answers = dns.resolver.resolve(hostname, 'AAAA')
            records['AAAA'] = [str(r) for r in answers]
        except:
            records['AAAA'] = []
        
        try:
            # MX records
            answers = dns.resolver.resolve(hostname, 'MX')
            records['MX'] = [str(r.exchange) for r in answers]
        except:
            records['MX'] = []
        
        try:
            # NS records
            answers = dns.resolver.resolve(hostname, 'NS')
            records['NS'] = [str(r) for r in answers]
        except:
            records['NS'] = []
        
        try:
            # TXT records
            answers = dns.resolver.resolve(hostname, 'TXT')
            records['TXT'] = [str(r) for r in answers]
        except:
            records['TXT'] = []
        
        self.results['dns_records'] = records
        
        # Вывод результатов
        for record_type, values in records.items():
            if values:
                print(f"{Fore.GREEN}✅ {record_type}: {', '.join(values[:3])}{Style.RESET_ALL}")
    
    async def scan_ports(self, ports: List[int] = None):
        """Сканирование портов"""
        if not ports:
            # Топ портов для сканирования
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 
                    445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        
        hostname = self.results['parsed_url']['hostname']
        open_ports = []
        
        print(f"{Fore.CYAN}🔍 Scanning {len(ports)} common ports...{Style.RESET_ALL}")
        
        async def check_port(port: int) -> Optional[Tuple[int, str]]:
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
        
        # Проверяем порты параллельно
        tasks = [check_port(port) for port in ports]
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
        """Определение сервисов на открытых портах"""
        if 'port_scan' not in self.results:
            return
        
        open_ports = self.results['port_scan']['open_ports']
        services = {}
        
        # Известные порты и сервисы
        common_services = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            111: 'RPC',
            135: 'MSRPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            1723: 'PPTP',
            3306: 'MySQL',
            3389: 'RDP',
            5900: 'VNC',
            8080: 'HTTP-Proxy',
            8443: 'HTTPS-Alt'
        }
        
        for port in open_ports:
            service_name = common_services.get(port, 'unknown')
            
            # Пробуем получить баннер
            banner = await self.get_banner(port)
            if banner:
                service_name = f"{service_name} ({banner[:50]})"
            
            services[port] = service_name
        
        self.results['services'] = services
    
    async def get_banner(self, port: int, timeout: float = 3.0) -> Optional[str]:
        """Получение баннера сервиса"""
        hostname = self.results['parsed_url']['hostname']
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port),
                timeout=timeout
            )
            
            # Отправляем простой запрос для HTTP/SSH и т.д.
            if port == 80 or port == 8080:
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
            elif port == 22:
                writer.write(b"SSH-2.0-DiamondEye\r\n")
            
            await writer.drain()
            
            # Читаем ответ
            banner = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
            
        except:
            return None
    
    async def ssl_scan(self):
        """Сканирование SSL/TLS конфигурации"""
        hostname = self.results['parsed_url']['hostname']
        port = self.results['parsed_url']['port'] or 443
        
        print(f"{Fore.CYAN}🔒 Checking SSL/TLS configuration...{Style.RESET_ALL}")
        
        ssl_info = {
            'supported': False,
            'certificate': {},
            'protocols': [],
            'ciphers': []
        }
        
        try:
            # Пробуем подключиться с SSL
            context = ssl.create_default_context()
            
            # Проверяем поддержку TLS 1.2/1.3
            for proto in [ssl.PROTOCOL_TLS, ssl.PROTOCOL_TLSv1_2, ssl.PROTOCOL_TLSv1_1]:
                try:
                    context = ssl.SSLContext(proto)
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(hostname, port, ssl=context),
                        timeout=5.0
                    )
                    
                    ssl_info['supported'] = True
                    ssl_info['protocols'].append(proto.__name__)
                    
                    # Получаем сертификат
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
                    
                except:
                    continue
        
        except Exception as e:
            ssl_info['error'] = str(e)
        
        self.results['ssl_info'] = ssl_info
        
        if ssl_info['supported']:
            print(f"{Fore.GREEN}✅ SSL/TLS supported{Style.RESET_ALL}")
            if ssl_info['certificate']:
                issuer = ssl_info['certificate']['issuer'].get('organizationName', 'Unknown')
                print(f"   Certificate issuer: {issuer}")
        else:
            print(f"{Fore.YELLOW}⚠️  No SSL/TLS support{Style.RESET_ALL}")
    
    async def find_subdomains(self, wordlist: List[str] = None):
        """Поиск поддоменов"""
        if not wordlist:
            wordlist = ['www', 'mail', 'ftp', 'admin', 'webmail', 'server', 
                       'ns1', 'ns2', 'cdn', 'api', 'blog', 'dev', 'test']
        
        hostname = self.results['parsed_url']['hostname']
        domain_parts = hostname.split('.')
        
        if len(domain_parts) > 2:
            # Уже поддомен
            return
        
        base_domain = '.'.join(domain_parts[-2:])  # example.com
        found_subdomains = []
        
        print(f"{Fore.CYAN}🔍 Looking for subdomains...{Style.RESET_ALL}")
        
        async def check_subdomain(sub: str) -> Optional[str]:
            full_domain = f"{sub}.{base_domain}"
            try:
                await asyncio.get_event_loop().getaddrinfo(full_domain, None)
                return full_domain
            except socket.gaierror:
                return None
        
        # Проверяем поддомены параллельно
        tasks = [check_subdomain(sub) for sub in wordlist]
        results = await asyncio.gather(*tasks)
        
        for subdomain in results:
            if subdomain:
                found_subdomains.append(subdomain)
                print(f"{Fore.GREEN}✅ Found: {subdomain}{Style.RESET_ALL}")
        
        self.results['subdomains'] = found_subdomains
    
    async def check_vulnerabilities(self):
        """Проверка общих уязвимостей"""
        print(f"{Fore.CYAN}⚠️  Checking for common vulnerabilities...{Style.RESET_ALL}")
        
        vulnerabilities = []
        hostname = self.results['parsed_url']['hostname']
        
        # Проверяем HTTP методы
        try:
            async with aiohttp.ClientSession() as session:
                async with session.options(f"http://{hostname}/", timeout=5) as resp:
                    allowed_methods = resp.headers.get('Allow', '')
                    if 'TRACE' in allowed_methods:
                        vulnerabilities.append({
                            'type': 'HTTP-TRACE',
                            'severity': 'medium',
                            'description': 'TRACE method enabled (cross-site tracing)'
                        })
        except:
            pass
        
        # Проверяем наличие phpinfo
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{hostname}/phpinfo.php", timeout=5) as resp:
                    if resp.status == 200 and 'phpinfo' in (await resp.text()).lower():
                        vulnerabilities.append({
                            'type': 'PHPINFO',
                            'severity': 'high',
                            'description': 'phpinfo.php file exposed'
                        })
        except:
            pass
        
        # Проверяем directory listing
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{hostname}/", timeout=5) as resp:
                    text = await resp.text()
                    if 'Index of /' in text or 'directory listing' in text.lower():
                        vulnerabilities.append({
                            'type': 'DIRECTORY_LISTING',
                            'severity': 'low',
                            'description': 'Directory listing enabled'
                        })
        except:
            pass
        
        self.results['vulnerabilities'] = vulnerabilities
        
        if vulnerabilities:
            for vuln in vulnerabilities:
                print(f"{Fore.RED}⚠️  {vuln['type']}: {vuln['description']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ No obvious vulnerabilities found{Style.RESET_ALL}")
    
    def generate_report(self, format: str = 'text') -> str:
        """Генерация отчета в указанном формате"""
        if format == 'json':
            return json.dumps(self.results, indent=2, default=str)
        
        # Текстовый отчет
        report = []
        report.append("=" * 60)
        report.append(f"RECONNAISSANCE REPORT - {self.target}")
        report.append("=" * 60)
        report.append(f"Scan time: {self.results['timestamp']}")
        report.append(f"Duration: {self.results['scan_duration']:.2f}s")
        report.append("")
        
        # DNS информация
        report.append("[DNS Records]")
        for record_type, values in self.results.get('dns_records', {}).items():
            if values:
                report.append(f"  {record_type}: {', '.join(values)}")
        
        # Открытые порты
        if 'port_scan' in self.results:
            report.append("")
            report.append("[Open Ports]")
            open_ports = self.results['port_scan']['open_ports']
            services = self.results.get('services', {})
            
            for port in open_ports:
                service = services.get(port, 'unknown')
                report.append(f"  {port}: {service}")
        
        # Уязвимости
        if 'vulnerabilities' in self.results and self.results['vulnerabilities']:
            report.append("")
            report.append("[Vulnerabilities Found]")
            for vuln in self.results['vulnerabilities']:
                report.append(f"  {vuln['type']} ({vuln['severity']}): {vuln['description']}")
        
        report.append("")
        report.append("=" * 60)
        
        return '\n'.join(report)


async def quick_recon(target: str) -> Dict[str, any]:
    """Быстрая разведка цели"""
    scanner = ReconScanner(target)
    results = await scanner.full_scan()
    
    print("\n" + scanner.generate_report())
    
    # Сохранение отчета
    filename = f"recon_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(results, f, indent=2, default=str)
    
    print(f"\n{Fore.GREEN}✅ Report saved to {filename}{Style.RESET_ALL}")
    
    return results