# proxy/manager.py
import asyncio
import aiohttp
import random
import time
import os
import hashlib
from typing import List, Optional, Dict, Set, Tuple
from dataclasses import dataclass, field
from collections import OrderedDict
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class Proxy:
    url: str
    type: str = 'http'
    latency: float = 0.0
    last_checked: float = 0
    failures: int = 0
    successes: int = 0
    country: Optional[str] = None
    anonymous: bool = False
    working: bool = True
    
    @property
    def success_rate(self) -> float:
        total = self.successes + self.failures
        if total == 0:
            return 1.0
        return self.successes / total
    
    @property
    def is_socks(self) -> bool:
        return self.type.startswith('socks')
    
    def to_dict(self) -> dict:
        return {
            'url': self.url,
            'type': self.type,
            'latency': self.latency,
            'success_rate': self.success_rate,
            'country': self.country,
            'anonymous': self.anonymous,
            'working': self.working
        }


class ProxyCache:
    def __init__(self, ttl: int = 300, max_size: int = 1000):
        self.ttl = ttl
        self.max_size = max_size
        self._cache: OrderedDict[str, Tuple[float, bool]] = OrderedDict()
        self._lock = asyncio.Lock()
    
    async def get(self, proxy_url: str) -> Optional[bool]:
        async with self._lock:
            if proxy_url in self._cache:
                timestamp, working = self._cache[proxy_url]
                if time.time() - timestamp < self.ttl:
                    self._cache.move_to_end(proxy_url)
                    return working
                else:
                    del self._cache[proxy_url]
        return None
    
    async def set(self, proxy_url: str, working: bool):
        async with self._lock:
            self._cache[proxy_url] = (time.time(), working)
            if len(self._cache) > self.max_size:
                self._cache.popitem(last=False)


class ProxyManager:
    def __init__(self, cache_ttl: int = 300, max_concurrent_checks: int = 100):
        self.proxies: List[Proxy] = []
        self.working_proxies: List[Proxy] = []
        self.blacklist: Set[str] = set()
        self._lock = asyncio.Lock()
        self._background_task: Optional[asyncio.Task] = None
        self._running = False
        self._current_index = 0
        self._cache = ProxyCache(ttl=cache_ttl)
        self._max_concurrent_checks = max_concurrent_checks
        
        self.PROXY_SOURCES = self._load_proxy_sources()
    
    def _load_proxy_sources(self) -> List[str]:
        sources = []
        sources_file = os.path.join(ROOT_DIR, "wordlists", "proxy_sources.txt")
        try:
            with open(sources_file, 'r') as f:
                sources = [line.strip() for line in f if line.strip()]
        except Exception as e:
            logger.warning(f"Failed to load proxy sources: {e}")
        if not sources:
            sources = [
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
                "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
            ]
        return sources
    
    async def load_from_file(self, filename: str):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                lines = [line.strip() for line in f if line.strip()]
            
            async with self._lock:
                for line in lines:
                    if line.startswith('#'):
                        continue
                    
                    proxy_type = 'http'
                    if line.startswith('socks4://'):
                        proxy_type = 'socks4'
                    elif line.startswith('socks5://'):
                        proxy_type = 'socks5'
                    elif not line.startswith(('http://', 'https://')):
                        line = f'http://{line}'
                    
                    proxy = Proxy(url=line, type=proxy_type)
                    self.proxies.append(proxy)
            
            logger.info(f"Loaded {len(lines)} proxies from {filename}")
            
        except FileNotFoundError:
            logger.error(f"Proxy file not found: {filename}")
        except Exception as e:
            logger.error(f"Failed to load proxies from {filename}: {e}")
    
    async def fetch_proxies(self):
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
                        for proxy_url, proxy_type in result:
                            proxy = Proxy(url=proxy_url, type=proxy_type)
                            self.proxies.append(proxy)
                            total += 1
            
            logger.info(f"Fetched {total} proxies from {len(self.PROXY_SOURCES)} sources")
    
    async def _fetch_from_source(self, session: aiohttp.ClientSession, url: str) -> List[Tuple[str, str]]:
        try:
            async with session.get(url, timeout=10) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    proxies = []
                    for line in text.splitlines():
                        line = line.strip()
                        if line and ':' in line:
                            if 'socks4' in url:
                                proxies.append((f"socks4://{line}", 'socks4'))
                            elif 'socks5' in url:
                                proxies.append((f"socks5://{line}", 'socks5'))
                            else:
                                proxies.append((f"http://{line}", 'http'))
                    return proxies
        except Exception as e:
            logger.debug(f"Failed to fetch from {url}: {e}")
        return []
    
    async def check_proxy(self, proxy: Proxy, timeout: float = 5.0) -> bool:
        if proxy.url in self.blacklist:
            return False
        
        cached = await self._cache.get(proxy.url)
        if cached is not None:
            return cached
        
        start = time.time()
        try:
            if proxy.is_socks:
                try:
                    from aiohttp_socks import ProxyConnector
                    connector = ProxyConnector.from_url(proxy.url)
                except ImportError:
                    logger.debug("aiohttp_socks not installed")
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
                        proxy.successes += 1
                        proxy.working = True
                        
                        if 'origin' in data:
                            proxy.anonymous = True
                        
                        await self._cache.set(proxy.url, True)
                        return True
        except Exception as e:
            logger.debug(f"Proxy {proxy.url} check failed: {e}")
        
        proxy.failures += 1
        proxy.working = False
        await self._cache.set(proxy.url, False)
        return False
    
    async def check_all(self, concurrency: int = 50, timeout: float = 5.0):
        concurrency = min(concurrency, self._max_concurrent_checks)
        logger.info(f"Checking {len(self.proxies)} proxies (concurrency={concurrency})...")
        
        semaphore = asyncio.Semaphore(concurrency)
        working = []
        
        async def check_with_limit(proxy: Proxy):
            async with semaphore:
                if await self.check_proxy(proxy, timeout):
                    working.append(proxy)
        
        tasks = [check_with_limit(p) for p in self.proxies]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        working.sort(key=lambda p: (p.latency, -p.success_rate))
        
        async with self._lock:
            self.working_proxies = working
        
        logger.info(f"Found {len(working)} working proxies")
        
        if working:
            avg_latency = sum(p.latency for p in working) / len(working)
            logger.info(f"Average latency: {avg_latency*1000:.1f}ms")
    
    async def background_check(self, interval: int = 300):
        self._running = True
        while self._running:
            await asyncio.sleep(interval)
            
            if not self._running:
                break
            
            logger.info("Running background proxy check...")
            
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
        if not self._background_task:
            self._background_task = asyncio.create_task(self.background_check(interval))
    
    async def stop_background_check(self):
        self._running = False
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass
            self._background_task = None
    
    def get_next_proxy(self) -> Optional[str]:
        if not self.working_proxies:
            return None
        
        proxy = self.working_proxies[self._current_index % len(self.working_proxies)]
        self._current_index += 1
        
        return proxy.url
    
    def get_random_proxy(self) -> Optional[str]:
        if not self.working_proxies:
            return None
        
        weights = [p.success_rate / (p.latency + 0.001) for p in self.working_proxies]
        total = sum(weights)
        if total == 0:
            return random.choice(self.working_proxies).url
        
        r = random.random() * total
        cumulative = 0
        for proxy, weight in zip(self.working_proxies, weights):
            cumulative += weight
            if r <= cumulative:
                return proxy.url
        
        return random.choice(self.working_proxies).url
    
    def get_fastest_proxy(self) -> Optional[str]:
        if not self.working_proxies:
            return None
        
        fastest = min(self.working_proxies, key=lambda p: p.latency)
        return fastest.url
    
    def get_proxies_by_country(self, country: str) -> List[Proxy]:
        return [p for p in self.working_proxies if p.country == country]
    
    def blacklist_proxy(self, proxy_url: str):
        self.blacklist.add(proxy_url)
        self.working_proxies = [p for p in self.working_proxies if p.url != proxy_url]
        asyncio.create_task(self._cache.set(proxy_url, False))
    
    def print_stats(self):
        if not self.working_proxies:
            print(f"{Fore.YELLOW}No working proxies available{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Proxy Statistics:{Style.RESET_ALL}")
        print(f"  Total proxies: {len(self.proxies)}")
        print(f"  Working: {len(self.working_proxies)}")
        print(f"  Blacklisted: {len(self.blacklist)}")
        
        types = {}
        for p in self.working_proxies:
            types[p.type] = types.get(p.type, 0) + 1
        
        for t, count in types.items():
            print(f"  {t.upper()}: {count}")
        
        if self.working_proxies:
            avg_latency = sum(p.latency for p in self.working_proxies) / len(self.working_proxies)
            avg_success = sum(p.success_rate for p in self.working_proxies) / len(self.working_proxies)
            print(f"  Average latency: {avg_latency*1000:.1f}ms")
            print(f"  Average success rate: {avg_success*100:.1f}%")
    
    async def close(self):
        await self.stop_background_check()