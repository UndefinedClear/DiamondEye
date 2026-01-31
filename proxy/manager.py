# proxy/manager.py
import aiohttp
import asyncio
import json
import random
import time
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse
import socket
from colorama import Fore, Style


@dataclass
class Proxy:
    """Класс для представления прокси"""
    host: str
    port: int
    protocol: str  # http, socks4, socks5
    country: str = ""
    latency: float = 9999.0
    last_check: datetime = field(default_factory=datetime.now)
    is_working: bool = False
    success_rate: float = 0.0
    speed_score: float = 0.0
    anonymity: str = "transparent"  # transparent, anonymous, elite
    
    def __str__(self):
        return f"{self.protocol}://{self.host}:{self.port}"
    
    def to_dict(self):
        return {
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol,
            'country': self.country,
            'latency': self.latency,
            'is_working': self.is_working,
            'success_rate': self.success_rate,
            'speed_score': self.speed_score,
            'anonymity': self.anonymity
        }


class ProxyManager:
    """Продвинутый менеджер прокси с авто-сбором и проверкой"""
    
    # Источники публичных прокси
    PROXY_SOURCES = [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4",
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5",
        "https://www.proxy-list.download/api/v1/get?type=http",
        "https://www.proxy-list.download/api/v1/get?type=https",
        "https://www.proxy-list.download/api/v1/get?type=socks4",
        "https://www.proxy-list.download/api/v1/get?type=socks5",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    ]
    
    # Тестовые URL для проверки прокси
    TEST_URLS = [
        "http://httpbin.org/ip",
        "http://httpbin.org/user-agent",
        "http://api.ipify.org?format=json",
        "https://api.ipify.org?format=json",
    ]
    
    def __init__(self, max_proxies: int = 1000):
        self.proxies: List[Proxy] = []
        self.max_proxies = max_proxies
        self.current_index = 0
        self._proxies_file = "proxies.json"
        self._cache_file = "proxy_cache.json"
        
        # Статистика
        self.stats = {
            'total_fetched': 0,
            'working_count': 0,
            'check_time': 0
        }
    
    async def fetch_proxies(self, force: bool = False) -> List[Proxy]:
        """Получение прокси из публичных источников"""
        print(f"{Fore.CYAN}🌐 Fetching proxies from {len(self.PROXY_SOURCES)} sources...{Style.RESET_ALL}")
        
        # Попробуем загрузить из кэша
        if not force and await self.load_from_cache():
            print(f"{Fore.GREEN}✅ Loaded {len(self.proxies)} proxies from cache{Style.RESET_ALL}")
            return self.proxies
        
        all_proxies = []
        
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            tasks = []
            for url in self.PROXY_SOURCES:
                task = asyncio.create_task(self._fetch_from_source(session, url))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    all_proxies.extend(result)
        
        # Убираем дубликаты
        unique_proxies = {}
        for proxy in all_proxies:
            key = f"{proxy.host}:{proxy.port}:{proxy.protocol}"
            if key not in unique_proxies:
                unique_proxies[key] = proxy
        
        self.proxies = list(unique_proxies.values())[:self.max_proxies]
        self.stats['total_fetched'] = len(self.proxies)
        
        print(f"{Fore.GREEN}✅ Fetched {len(self.proxies)} unique proxies{Style.RESET_ALL}")
        
        # Сохраняем в кэш
        await self.save_to_cache()
        
        return self.proxies
    
    async def _fetch_from_source(self, session: aiohttp.ClientSession, url: str) -> List[Proxy]:
        """Получение прокси из одного источника"""
        proxies = []
        try:
            async with session.get(url, headers={
                'User-Agent': 'Mozilla/5.0 (DiamondEye/10.0)'
            }) as response:
                if response.status == 200:
                    text = await response.text()
                    
                    # Определяем протокол из URL
                    protocol = 'http'
                    if 'socks4' in url:
                        protocol = 'socks4'
                    elif 'socks5' in url:
                        protocol = 'socks5'
                    
                    for line in text.strip().split('\n'):
                        line = line.strip()
                        if ':' in line:
                            parts = line.split(':')
                            if len(parts) >= 2:
                                host = parts[0].strip()
                                try:
                                    port = int(parts[1].strip())
                                    if 1 <= port <= 65535:
                                        proxy = Proxy(host=host, port=port, protocol=protocol)
                                        proxies.append(proxy)
                                except ValueError:
                                    continue
        except Exception as e:
            if 'debug' in globals() and globals()['debug']:
                print(f"{Fore.YELLOW}⚠️  Failed to fetch from {url}: {e}{Style.RESET_ALL}")
        
        return proxies
    
    async def load_from_file(self, filepath: str) -> bool:
        """Загрузка прокси из файла"""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith('#'):
                    # Поддерживаем разные форматы:
                    # host:port
                    # protocol://host:port
                    # host:port:protocol
                    
                    if '://' in line:
                        parsed = urlparse(line)
                        protocol = parsed.scheme
                        host = parsed.hostname
                        port = parsed.port or (443 if protocol == 'https' else 80)
                    elif line.count(':') == 2:
                        # host:port:protocol
                        host, port_str, protocol = line.split(':')
                        port = int(port_str)
                    else:
                        # host:port (по умолчанию HTTP)
                        host, port_str = line.split(':')
                        port = int(port_str)
                        protocol = 'http'
                    
                    if host and port:
                        proxy = Proxy(host=host, port=port, protocol=protocol)
                        self.proxies.append(proxy)
            
            print(f"{Fore.GREEN}✅ Loaded {len(self.proxies)} proxies from {filepath}{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to load proxies from {filepath}: {e}{Style.RESET_ALL}")
            return False
    
    async def check_proxy(self, proxy: Proxy, timeout: float = 5.0) -> bool:
        """Проверка работоспособности прокси"""
        start_time = time.time()
        
        # Пропускаем недопустимые прокси
        if not proxy.host or proxy.port <= 0 or proxy.port > 65535:
            proxy.is_working = False
            return False
        
        test_url = random.choice(self.TEST_URLS)
        
        try:
            connector = None
            if proxy.protocol.startswith('socks'):
                try:
                    from aiohttp_socks import ProxyConnector
                    connector = ProxyConnector.from_url(
                        f"{proxy.protocol}://{proxy.host}:{proxy.port}",
                        rdns=True
                    )
                except ImportError:
                    print(f"{Fore.YELLOW}⚠️  Install aiohttp_socks for SOCKS support: pip install aiohttp-socks{Style.RESET_ALL}")
                    proxy.is_working = False
                    return False
            else:
                connector = aiohttp.TCPConnector(ssl=False)
            
            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=timeout)
            ) as session:
                async with session.get(
                    test_url,
                    headers={'User-Agent': 'Mozilla/5.0 (ProxyTester)'},
                    ssl=False
                ) as response:
                    if response.status == 200:
                        # Проверяем анонимность
                        try:
                            data = await response.json()
                            if 'origin' in data:
                                if data['origin'] == proxy.host:
                                    proxy.anonymity = "transparent"
                                else:
                                    proxy.anonymity = "anonymous"
                        except:
                            proxy.anonymity = "unknown"
                        
                        proxy.latency = (time.time() - start_time) * 1000  # в мс
                        proxy.last_check = datetime.now()
                        proxy.is_working = True
                        proxy.success_rate = min(1.0, proxy.success_rate + 0.1)
                        
                        # Оценка скорости
                        if proxy.latency < 100:
                            proxy.speed_score = 1.0
                        elif proxy.latency < 500:
                            proxy.speed_score = 0.7
                        elif proxy.latency < 1000:
                            proxy.speed_score = 0.4
                        else:
                            proxy.speed_score = 0.1
                        
                        return True
        
        except (aiohttp.ClientError, asyncio.TimeoutError, socket.gaierror):
            pass
        except Exception as e:
            if 'debug' in globals() and globals()['debug']:
                print(f"{Fore.YELLOW}⚠️  Proxy check error for {proxy}: {e}{Style.RESET_ALL}")
        
        proxy.is_working = False
        proxy.success_rate = max(0.0, proxy.success_rate - 0.2)
        return False
    
    async def check_all(self, concurrency: int = 50, timeout: float = 5.0):
        """Массовая проверка всех прокси"""
        if not self.proxies:
            print(f"{Fore.YELLOW}⚠️  No proxies to check{Style.RESET_ALL}")
            return
        
        print(f"{Fore.CYAN}🔍 Checking {len(self.proxies)} proxies (concurrency: {concurrency})...{Style.RESET_ALL}")
        
        semaphore = asyncio.Semaphore(concurrency)
        start_time = time.time()
        
        async def check_with_semaphore(proxy: Proxy):
            async with semaphore:
                await self.check_proxy(proxy, timeout)
        
        # Создаем задачи для проверки
        tasks = [check_with_semaphore(p) for p in self.proxies]
        
        # Разбиваем на батчи для прогресс-бара
        batch_size = 100
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
            
            # Прогресс
            checked = min(i + batch_size, len(tasks))
            working = len([p for p in self.proxies[:checked] if p.is_working])
            print(f"\r{Fore.CYAN}📊 Progress: {checked}/{len(tasks)} | Working: {working}{Style.RESET_ALL}", end="")
        
        print()  # Новая строка после прогресс-бара
        
        # Фильтруем неработающие прокси
        self.proxies = [p for p in self.proxies if p.is_working]
        self.stats['working_count'] = len(self.proxies)
        self.stats['check_time'] = time.time() - start_time
        
        print(f"{Fore.GREEN}✅ Check complete: {len(self.proxies)} working proxies{Style.RESET_ALL}")
        
        # Сохраняем работающие прокси
        await self.save_working_proxies()
    
    def get_next_proxy(self) -> Optional[str]:
        """Получение следующего прокси (ротация)"""
        if not self.proxies:
            return None
        
        # Выбираем случайный рабочий прокси с учетом скорости
        working_proxies = [p for p in self.proxies if p.is_working]
        if not working_proxies:
            return None
        
        # Взвешенный случайный выбор (предпочтение быстрым прокси)
        weights = [p.speed_score * p.success_rate for p in working_proxies]
        if sum(weights) > 0:
            proxy = random.choices(working_proxies, weights=weights, k=1)[0]
        else:
            proxy = random.choice(working_proxies)
        
        return str(proxy)
    
    def get_fastest(self, count: int = 10) -> List[Proxy]:
        """Получение самых быстрых прокси"""
        working = [p for p in self.proxies if p.is_working]
        sorted_proxies = sorted(working, key=lambda x: x.latency)
        return sorted_proxies[:min(count, len(sorted_proxies))]
    
    async def save_working_proxies(self, filepath: str = "working_proxies.txt"):
        """Сохранение рабочих прокси в файл"""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for proxy in self.proxies:
                    if proxy.is_working:
                        f.write(f"{proxy}\n")
            
            print(f"{Fore.GREEN}✅ Saved {len(self.proxies)} working proxies to {filepath}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to save proxies: {e}{Style.RESET_ALL}")
    
    async def save_to_cache(self):
        """Сохранение прокси в кэш"""
        try:
            data = {
                'proxies': [p.to_dict() for p in self.proxies],
                'timestamp': datetime.now().isoformat(),
                'stats': self.stats
            }
            
            with open(self._cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
            
            return True
        except Exception as e:
            if 'debug' in globals() and globals()['debug']:
                print(f"{Fore.YELLOW}⚠️  Cache save failed: {e}{Style.RESET_ALL}")
            return False
    
    async def load_from_cache(self) -> bool:
        """Загрузка прокси из кэша"""
        try:
            with open(self._cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Проверяем свежесть кэша (не старше 24 часов)
            cache_time = datetime.fromisoformat(data['timestamp'])
            if (datetime.now() - cache_time).total_seconds() > 24 * 3600:
                print(f"{Fore.YELLOW}⚠️  Proxy cache is older than 24 hours{Style.RESET_ALL}")
                return False
            
            self.proxies = []
            for proxy_data in data.get('proxies', []):
                proxy = Proxy(
                    host=proxy_data['host'],
                    port=proxy_data['port'],
                    protocol=proxy_data['protocol'],
                    country=proxy_data.get('country', ''),
                    latency=proxy_data.get('latency', 9999.0),
                    is_working=proxy_data.get('is_working', False),
                    success_rate=proxy_data.get('success_rate', 0.0),
                    speed_score=proxy_data.get('speed_score', 0.0),
                    anonymity=proxy_data.get('anonymity', 'transparent')
                )
                proxy.last_check = datetime.fromisoformat(proxy_data['last_check'])
                self.proxies.append(proxy)
            
            self.stats = data.get('stats', self.stats)
            return True
            
        except FileNotFoundError:
            return False
        except Exception as e:
            if 'debug' in globals() and globals()['debug']:
                print(f"{Fore.YELLOW}⚠️  Cache load failed: {e}{Style.RESET_ALL}")
            return False
    
    def print_stats(self):
        """Вывод статистики прокси"""
        working = len([p for p in self.proxies if p.is_working])
        total = len(self.proxies)
        
        print(f"\n{Fore.CYAN}📊 Proxy Statistics:{Style.RESET_ALL}")
        print(f"   Total proxies: {total}")
        print(f"   Working proxies: {working} ({working/total*100:.1f}%)")
        
        if working > 0:
            avg_latency = sum(p.latency for p in self.proxies if p.is_working) / working
            fast_proxies = len([p for p in self.proxies if p.is_working and p.latency < 500])
            
            print(f"   Average latency: {avg_latency:.0f} ms")
            print(f"   Fast proxies (<500ms): {fast_proxies}")
            
            # Распределение по протоколам
            protocols = {}
            for p in self.proxies:
                if p.is_working:
                    protocols[p.protocol] = protocols.get(p.protocol, 0) + 1
            
            print(f"   By protocol:")
            for proto, count in protocols.items():
                print(f"     {proto}: {count}")