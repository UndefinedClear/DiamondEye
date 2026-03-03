# proxy/manager.py
import aiohttp
import asyncio
import json
import random
import time
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlparse
import socket
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)


@dataclass
class Proxy:
    """Класс для представления прокси."""
    host: str
    port: int
    protocol: str  # http, socks4, socks5
    username: Optional[str] = None
    password: Optional[str] = None
    country: str = ""
    latency: float = 9999.0
    last_check: datetime = field(default_factory=datetime.now)
    is_working: bool = False
    success_rate: float = 0.0
    speed_score: float = 0.0
    anonymity: str = "transparent"  # transparent, anonymous, elite

    def __str__(self):
        auth = f"{self.username}:{self.password}@" if self.username and self.password else ""
        return f"{self.protocol}://{auth}{self.host}:{self.port}"

    def to_dict(self):
        return {
            'host': self.host,
            'port': self.port,
            'protocol': self.protocol,
            'username': self.username,
            'password': self.password,
            'country': self.country,
            'latency': self.latency,
            'is_working': self.is_working,
            'success_rate': self.success_rate,
            'speed_score': self.speed_score,
            'anonymity': self.anonymity
        }


class ProxyManager:
    """Продвинутый менеджер прокси с авто-сбором, проверкой и фоновым обновлением."""

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

    TEST_URLS = [
        "http://httpbin.org/ip",
        "http://httpbin.org/user-agent",
        "http://api.ipify.org?format=json",
        "https://api.ipify.org?format=json",
    ]

    def __init__(self, max_proxies: int = 1000, background_check_interval: int = 300):
        self.proxies: List[Proxy] = []
        self.max_proxies = max_proxies
        self.current_index = 0
        self._proxies_file = "proxies.json"
        self._cache_file = "proxy_cache.json"
        self._background_task: Optional[asyncio.Task] = None
        self._check_interval = background_check_interval

        self.stats = {
            'total_fetched': 0,
            'working_count': 0,
            'check_time': 0
        }

    async def start_background_check(self):
        """Запуск фоновой задачи для периодической проверки прокси."""
        self._background_task = asyncio.create_task(self._background_checker())

    async def stop_background_check(self):
        """Остановка фоновой проверки."""
        if self._background_task:
            self._background_task.cancel()
            try:
                await self._background_task
            except asyncio.CancelledError:
                pass

    async def _background_checker(self):
        """Фоновая проверка прокси с заданным интервалом."""
        while True:
            await asyncio.sleep(self._check_interval)
            logger.info("Background proxy check started")
            await self.check_all(concurrency=50, timeout=5.0, update_only=True)
            logger.info(f"Background check finished, working proxies: {self.stats['working_count']}")

    async def fetch_proxies(self, force: bool = False) -> List[Proxy]:
        """Получение прокси из публичных источников."""
        logger.info(f"Fetching proxies from {len(self.PROXY_SOURCES)} sources...")
        if not force and await self.load_from_cache():
            logger.info(f"Loaded {len(self.proxies)} proxies from cache")
            return self.proxies

        all_proxies = []
        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=30)
        ) as session:
            tasks = [self._fetch_from_source(session, url) for url in self.PROXY_SOURCES]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    all_proxies.extend(result)

        # Убираем дубликаты
        unique = {}
        for p in all_proxies:
            key = f"{p.host}:{p.port}:{p.protocol}"
            if key not in unique:
                unique[key] = p

        self.proxies = list(unique.values())[:self.max_proxies]
        self.stats['total_fetched'] = len(self.proxies)
        logger.info(f"Fetched {len(self.proxies)} unique proxies")
        await self.save_to_cache()
        return self.proxies

    async def _fetch_from_source(self, session: aiohttp.ClientSession, url: str) -> List[Proxy]:
        proxies = []
        try:
            async with session.get(url, headers={'User-Agent': 'Mozilla/5.0 (DiamondEye/10.0)'}) as resp:
                if resp.status == 200:
                    text = await resp.text()
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
            logger.debug(f"Failed to fetch from {url}: {e}")
        return proxies

    async def load_from_file(self, filepath: str) -> bool:
        """Загрузка прокси из файла (поддерживает авторизацию)."""
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                # Форматы:
                # protocol://user:pass@host:port
                # protocol://host:port
                # host:port
                # host:port:protocol
                # host:port:protocol:user:pass
                if '://' in line:
                    parsed = urlparse(line)
                    protocol = parsed.scheme
                    host = parsed.hostname
                    port = parsed.port
                    username = parsed.username
                    password = parsed.password
                elif line.count(':') == 4:
                    # host:port:protocol:user:pass
                    host, port_str, protocol, username, password = line.split(':')
                    port = int(port_str)
                elif line.count(':') == 2:
                    # host:port:protocol
                    host, port_str, protocol = line.split(':')
                    port = int(port_str)
                    username = password = None
                else:
                    # host:port
                    host, port_str = line.split(':')
                    port = int(port_str)
                    protocol = 'http'
                    username = password = None

                if host and port:
                    proxy = Proxy(host=host, port=port, protocol=protocol,
                                  username=username, password=password)
                    self.proxies.append(proxy)
            logger.info(f"Loaded {len(self.proxies)} proxies from {filepath}")
            return True
        except Exception as e:
            logger.error(f"Failed to load proxies from {filepath}: {e}")
            return False

    async def check_proxy(self, proxy: Proxy, timeout: float = 5.0) -> bool:
        """Проверка работоспособности одного прокси."""
        start_time = time.time()
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
                        str(proxy), rdns=True
                    )
                except ImportError:
                    logger.warning("aiohttp_socks not installed, skipping SOCKS proxies")
                    proxy.is_working = False
                    return False
            else:
                connector = aiohttp.TCPConnector(ssl=False)

            # Поддержка авторизации
            auth = None
            if proxy.username and proxy.password:
                auth = aiohttp.BasicAuth(proxy.username, proxy.password)

            async with aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=timeout),
                auth=auth
            ) as session:
                async with session.get(
                    test_url,
                    headers={'User-Agent': 'Mozilla/5.0 (ProxyTester)'},
                    ssl=False
                ) as response:
                    if response.status == 200:
                        # Анонимность
                        try:
                            data = await response.json()
                            if 'origin' in data:
                                if data['origin'] == proxy.host:
                                    proxy.anonymity = "transparent"
                                else:
                                    proxy.anonymity = "anonymous"
                        except:
                            proxy.anonymity = "unknown"

                        proxy.latency = (time.time() - start_time) * 1000
                        proxy.last_check = datetime.now()
                        proxy.is_working = True
                        proxy.success_rate = min(1.0, proxy.success_rate + 0.1)

                        if proxy.latency < 100:
                            proxy.speed_score = 1.0
                        elif proxy.latency < 500:
                            proxy.speed_score = 0.7
                        elif proxy.latency < 1000:
                            proxy.speed_score = 0.4
                        else:
                            proxy.speed_score = 0.1
                        return True

        except Exception as e:
            logger.debug(f"Proxy check failed for {proxy}: {e}")

        proxy.is_working = False
        proxy.success_rate = max(0.0, proxy.success_rate - 0.2)
        return False

    async def check_all(self, concurrency: int = 50, timeout: float = 5.0, update_only: bool = False):
        """Массовая проверка всех прокси."""
        if not self.proxies:
            logger.warning("No proxies to check")
            return

        logger.info(f"Checking {len(self.proxies)} proxies (concurrency: {concurrency})...")
        semaphore = asyncio.Semaphore(concurrency)
        start_time = time.time()

        async def check_with_semaphore(proxy: Proxy):
            async with semaphore:
                # Если update_only=True, проверяем только те, что давно не проверялись
                if update_only and (datetime.now() - proxy.last_check).total_seconds() < self._check_interval:
                    return
                await self.check_proxy(proxy, timeout)

        tasks = [check_with_semaphore(p) for p in self.proxies]
        batch_size = 100
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i + batch_size]
            await asyncio.gather(*batch, return_exceptions=True)
            working = len([p for p in self.proxies[:i + batch_size] if p.is_working])
            logger.debug(f"Progress: {min(i + batch_size, len(tasks))}/{len(tasks)} | Working: {working}")

        # Фильтруем неработающие
        self.proxies = [p for p in self.proxies if p.is_working]
        self.stats['working_count'] = len(self.proxies)
        self.stats['check_time'] = time.time() - start_time
        logger.info(f"Check complete: {len(self.proxies)} working proxies")

        await self.save_working_proxies()

    def get_next_proxy(self) -> Optional[str]:
        """Получение следующего прокси (ротация с учётом скорости)."""
        working = [p for p in self.proxies if p.is_working]
        if not working:
            return None
        weights = [p.speed_score * p.success_rate for p in working]
        if sum(weights) > 0:
            proxy = random.choices(working, weights=weights, k=1)[0]
        else:
            proxy = random.choice(working)
        return str(proxy)

    def get_fastest(self, count: int = 10) -> List[Proxy]:
        """Возвращает самые быстрые прокси."""
        working = [p for p in self.proxies if p.is_working]
        return sorted(working, key=lambda x: x.latency)[:min(count, len(working))]

    async def save_working_proxies(self, filepath: str = "working_proxies.txt"):
        """Сохраняет рабочие прокси в файл."""
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                for p in self.proxies:
                    if p.is_working:
                        f.write(f"{p}\n")
            logger.info(f"Saved {len(self.proxies)} working proxies to {filepath}")
        except Exception as e:
            logger.error(f"Failed to save proxies: {e}")

    async def save_to_cache(self):
        """Сохраняет прокси в кэш."""
        try:
            data = {
                'proxies': [p.to_dict() for p in self.proxies],
                'timestamp': datetime.now().isoformat(),
                'stats': self.stats
            }
            with open(self._cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.debug(f"Cache save failed: {e}")

    async def load_from_cache(self) -> bool:
        """Загружает прокси из кэша, если он не старше 24 часов."""
        try:
            with open(self._cache_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            cache_time = datetime.fromisoformat(data['timestamp'])
            if (datetime.now() - cache_time).total_seconds() > 24 * 3600:
                logger.info("Proxy cache is older than 24 hours")
                return False
            self.proxies = []
            for pd in data.get('proxies', []):
                p = Proxy(
                    host=pd['host'], port=pd['port'], protocol=pd['protocol'],
                    username=pd.get('username'), password=pd.get('password'),
                    country=pd.get('country', ''), latency=pd.get('latency', 9999.0),
                    is_working=pd.get('is_working', False),
                    success_rate=pd.get('success_rate', 0.0),
                    speed_score=pd.get('speed_score', 0.0),
                    anonymity=pd.get('anonymity', 'transparent')
                )
                p.last_check = datetime.fromisoformat(pd['last_check'])
                self.proxies.append(p)
            self.stats = data.get('stats', self.stats)
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            logger.debug(f"Cache load failed: {e}")
            return False

    def print_stats(self):
        """Вывод статистики."""
        working = len([p for p in self.proxies if p.is_working])
        total = len(self.proxies)
        print(f"\n{Fore.CYAN}📊 Proxy Statistics:{Style.RESET_ALL}")
        print(f"   Total proxies: {total}")
        print(f"   Working proxies: {working} ({working/total*100:.1f}%)")
        if working > 0:
            avg_lat = sum(p.latency for p in self.proxies if p.is_working) / working
            fast = len([p for p in self.proxies if p.is_working and p.latency < 500])
            print(f"   Average latency: {avg_lat:.0f} ms")
            print(f"   Fast proxies (<500ms): {fast}")
            protocols = {}
            for p in self.proxies:
                if p.is_working:
                    protocols[p.protocol] = protocols.get(p.protocol, 0) + 1
            print(f"   By protocol:")
            for proto, cnt in protocols.items():
                print(f"     {proto}: {cnt}")