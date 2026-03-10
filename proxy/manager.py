# proxy/manager.py
import asyncio
import aiohttp
import random
import time
from typing import List, Optional, Dict, Set
from dataclasses import dataclass
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)


@dataclass
class Proxy:
    """Прокси с метаданными."""
    url: str  # http://user:pass@host:port или http://host:port
    type: str = 'http'  # http, https, socks4, socks5
    latency: float = 0.0
    last_checked: float = 0
    failures: int = 0
    country: Optional[str] = None
    anonymous: bool = False
    working: bool = True
    
    @property
    def is_socks(self) -> bool:
        return self.type.startswith('socks')
    
    def to_dict(self) -> dict:
        return {
            'url': self.url,
            'type': self.type,
            'latency': self.latency,
            'country': self.country,
            'anonymous': self.anonymous,
            'working': self.working
        }


class ProxyManager:
    """
    Менеджер прокси с автоматической проверкой и ротацией.
    """
    
    # Публичные источники прокси
    PROXY_SOURCES = [
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
        "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
        "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
        "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
    ]
    
    def __init__(self):
        self.proxies: List[Proxy] = []
        self.working_proxies: List[Proxy] = []
        self.blacklist: Set[str] = set()
        self._lock = asyncio.Lock()
        self._background_task: Optional[asyncio.Task] = None
        self._running = False
        self._current_index = 0
        
    async def load_from_file(self, filename: str):
        """Загрузка прокси из файла."""
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
            
            async with self._lock:
                for line in lines:
                    # Пропускаем комментарии
                    if line.startswith('#'):
                        continue
                    
                    # Добавляем схему если нет
                    if not line.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                        line = f'http://{line}'
                    
                    proxy = Proxy(url=line)
                    self.proxies.append(proxy)
            
            logger.info(f"Loaded {len(lines)} proxies from {filename}")
            
        except Exception as e:
            logger.error(f"Failed to load proxies from {filename}: {e}")
    
    async def fetch_proxies(self):
        """Автоматический сбор прокси из публичных источников."""
        logger.info("Fetching proxies from public sources...")
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url in self.PROXY_SOURCES:
                tasks.append(self._fetch_from_source(session, url))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            total = 0
            async with self._lock:
                for result in results:
                    if isinstance(result, list):
                        for proxy_url in result:
                            proxy_type = 'http'
                            if 'socks4' in proxy_url:
                                proxy_type = 'socks4'
                            elif 'socks5' in proxy_url:
                                proxy_type = 'socks5'
                            
                            proxy = Proxy(url=proxy_url, type=proxy_type)
                            self.proxies.append(proxy)
                            total += 1
            
            logger.info(f"Fetched {total} proxies from {len(self.PROXY_SOURCES)} sources")
    
    async def _fetch_from_source(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        """Загрузка прокси из одного источника."""
        try:
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    proxies = []
                    for line in text.splitlines():
                        line = line.strip()
                        if line and ':' in line:
                            # Добавляем схему
                            if 'socks4' in url:
                                proxies.append(f"socks4://{line}")
                            elif 'socks5' in url:
                                proxies.append(f"socks5://{line}")
                            else:
                                proxies.append(f"http://{line}")
                    return proxies
        except Exception as e:
            logger.debug(f"Failed to fetch from {url}: {e}")
        return []
    
    async def check_proxy(self, proxy: Proxy, timeout: float = 5.0) -> bool:
        """Проверка работоспособности прокси."""
        if proxy.url in self.blacklist:
            return False
        
        start = time.time()
        try:
            connector = None
            if proxy.is_socks:
                try:
                    from aiohttp_socks import ProxyConnector
                    connector = ProxyConnector.from_url(proxy.url)
                except ImportError:
                    logger.debug("aiohttp_socks not installed, skipping SOCKS proxy")
                    return False
            else:
                connector = aiohttp.TCPConnector()
            
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    'http://httpbin.org/ip',
                    timeout=timeout,
                    proxy=proxy.url if not proxy.is_socks else None
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        proxy.latency = time.time() - start
                        proxy.last_checked = time.time()
                        proxy.working = True
                        
                        # Проверка на анонимность
                        if 'origin' in data:
                            proxy.anonymous = True
                        
                        return True
        except Exception as e:
            logger.debug(f"Proxy {proxy.url} check failed: {e}")
        
        proxy.failures += 1
        proxy.working = False
        return False
    
    async def check_all(self, concurrency: int = 50, timeout: float = 5.0):
        """Проверка всех прокси."""
        logger.info(f"Checking {len(self.proxies)} proxies (concurrency={concurrency})...")
        
        semaphore = asyncio.Semaphore(concurrency)
        working = []
        
        async def check_with_limit(proxy: Proxy):
            async with semaphore:
                if await self.check_proxy(proxy, timeout):
                    working.append(proxy)
        
        tasks = [check_with_limit(p) for p in self.proxies]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        async with self._lock:
            self.working_proxies = working
        
        logger.info(f"Found {len(working)} working proxies")
    
    async def background_check(self, interval: int = 300):
        """Фоновая проверка прокси."""
        self._running = True
        while self._running:
            await asyncio.sleep(interval)
            
            if not self._running:
                break
            
            logger.info("Running background proxy check...")
            
            # Проверяем рабочие прокси
            working_copy = self.working_proxies.copy()
            still_working = []
            
            semaphore = asyncio.Semaphore(20)
            
            async def check_working(proxy: Proxy):
                async with semaphore:
                    if await self.check_proxy(proxy):
                        still_working.append(proxy)
                    else:
                        async with self._lock:
                            if proxy in self.working_proxies:
                                self.working_proxies.remove(proxy)
            
            tasks = [check_working(p) for p in working_copy]
            await asyncio.gather(*tasks, return_exceptions=True)
            
            logger.info(f"Background check: {len(still_working)}/{len(working_copy)} proxies still working")
    
    async def start_background_check(self, interval: int = 300):
        """Запуск фоновой проверки."""
        if not self._background_task:
            self._background_task = asyncio.create_task(self.background_check(interval))
    
    async def stop_background_check(self):
        """Остановка фоновой проверки."""
        self._running = False
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
            self._background_task = None
    
    def get_next_proxy(self) -> Optional[str]:
        """Получение следующего рабочего прокси (round-robin)."""
        if not self.working_proxies:
            return None
        
        proxy = self.working_proxies[self._current_index % len(self.working_proxies)]
        self._current_index += 1
        
        return proxy.url
    
    def get_random_proxy(self) -> Optional[str]:
        """Получение случайного рабочего прокси."""
        if not self.working_proxies:
            return None
        
        return random.choice(self.working_proxies).url
    
    def get_proxies_by_country(self, country: str) -> List[Proxy]:
        """Получение прокси по стране."""
        return [p for p in self.working_proxies if p.country == country]
    
    def blacklist_proxy(self, proxy_url: str):
        """Добавление прокси в черный список."""
        self.blacklist.add(proxy_url)
        
        # Удаляем из рабочих
        self.working_proxies = [p for p in self.working_proxies if p.url != proxy_url]
    
    def print_stats(self):
        """Вывод статистики."""
        if not self.working_proxies:
            print(f"{Fore.YELLOW}⚠️  No working proxies available{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}📡 Proxy Statistics:{Style.RESET_ALL}")
        print(f"  Total proxies: {len(self.proxies)}")
        print(f"  Working: {len(self.working_proxies)}")
        print(f"  Blacklisted: {len(self.blacklist)}")
        
        # Статистика по типам
        types = {}
        for p in self.working_proxies:
            types[p.type] = types.get(p.type, 0) + 1
        
        for t, count in types.items():
            print(f"  {t.upper()}: {count}")
        
        # Средняя задержка
        if self.working_proxies:
            avg_latency = sum(p.latency for p in self.working_proxies) / len(self.working_proxies)
            print(f"  Average latency: {avg_latency*1000:.1f}ms")
    
    async def close(self):
        """Закрытие менеджера."""
        await self.stop_background_check()