#!/usr/bin/env python3
"""
💎 DiamondEye v7.1 — CTF & Local Server Edition (баги исправлены)
"""
import asyncio
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    print("\033[96m⚡ uvloop activated — speed boost enabled\033[0m")
except ImportError:
    print("\033[93mℹ️  uvloop not available — using default asyncio\033[0m")

import time
import signal
import sys
import psutil
from urllib.parse import urlparse
import json
import argparse  # ✅ Добавлено для Namespace

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from args import parse_args
from attack import DiamondEyeAttack
from colorama import Fore, Style


def load_useragents(filepath: str) -> list:
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[DEBUG] Failed to load useragents: {e}{Style.RESET_ALL}")
        return []


def parse_methods(raw: str) -> list:
    ALL_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS', 'HEAD']
    if not raw:
        return ['GET']
    if raw.upper() == 'ALL':
        return ALL_METHODS
    return [m.strip().upper() for m in raw.split(',') if m.strip().upper() in ALL_METHODS]


async def main():
    args = parse_args()

    # ✅ Проверка: --http2 + --extreme
    if args.http2 and args.extreme:
        print(f"{Fore.YELLOW}⚠️  --http2 несовместим с --extreme — отключено{Style.RESET_ALL}")
        args.http2 = False

    # ✅ Проверка: --header-flood без --junk
    if args.header_flood and not args.junk:
        print(f"{Fore.YELLOW}⚠️  --header-flood требует --junk — включен автоматически{Style.RESET_ALL}")
        args.junk = True

    # ✅ Проверка: --flood + --slow
    if args.flood and args.slow > 0:
        print(f"{Fore.YELLOW}⚠️  --flood + --slow — режимы конфликтуют. --slow отключён{Style.RESET_ALL}")
        args.slow = 0.0

    # Validate URL
    if not args.url:
        print(f"{Fore.RED}❌ URL is required{Style.RESET_ALL}")
        sys.exit(1)
    try:
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            print(f"{Fore.RED}❌ Invalid URL{Style.RESET_ALL}")
            sys.exit(1)
    except Exception:
        print(f"{Fore.RED}❌ URL parse error{Style.RESET_ALL}")
        sys.exit(1)

    # Load useragents
    useragents = load_useragents(args.useragents) if args.useragents else []

    if "127.0.0.1" in args.url or "localhost" in args.url:
        useragents.append("CTF-Scanner/7.1")
        useragents.append("Mozilla/5.0 (X11; Linux x86_64) CTF-Mode")

    methods = parse_methods(args.methods)

    if "127.0.0.1" in args.url or "localhost" in args.url:
        max_workers = max(1, psutil.cpu_count() * 4)
        if args.workers > max_workers:
            print(f"{Fore.YELLOW}🔧 Localhost: workers limited to {max_workers}{Style.RESET_ALL}")
            args.workers = max_workers

    attack = DiamondEyeAttack(
        url=args.url,
        workers=args.workers,
        sockets=args.sockets,
        methods=methods,
        useragents=useragents,
        no_ssl_check=args.no_ssl_check,
        debug=args.debug,
        proxy=args.proxy,
        use_http2=args.http2,
        slow_rate=args.slow,
        extreme=args.extreme,
        data_size=args.data_size,
        flood=args.flood,
        path_fuzz=args.path_fuzz,
        header_flood=args.header_flood,
        method_fuzz=args.method_fuzz,
        args=args
    )

    def signal_handler():
        if not hasattr(attack, '_shutdown_event') or attack._shutdown_event.is_set():
            return
        print(f"\n{Fore.RED}🛑 Stopping attack...{Style.RESET_ALL}")
        attack._shutdown_event.set()
        if attack._monitor_task:
            attack._monitor_task.cancel()
        if attack._rps_task:
            attack._rps_task.cancel()

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)
    except NotImplementedError:
        pass

    start_time = time.time()
    try:
        print(f"{Fore.GREEN}🚀 DiamondEye v7.1 — Attack started{Style.RESET_ALL}")
        await attack.start()
    except Exception as e:
        if args.debug:
            print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
    finally:
        await attack.shutdown()
        attack.print_stats()
        print(f"\n{Fore.GREEN}✅ Attack finished{Style.RESET_ALL}")

    duration = time.time() - start_time
    if args.log:
        try:
            report = generate_report(attack, duration, args)
            with open(args.log, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"{Fore.CYAN}📝 Report saved: {args.log}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Log error: {e}{Style.RESET_ALL}")

    if args.json:
        try:
            save_json_report(attack, duration, args, args.json)
            print(f"{Fore.CYAN}📦 JSON saved: {args.json}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ JSON error: {e}{Style.RESET_ALL}")

    if args.plot:
        save_plot(attack, args.plot)


# ... остальные функции (generate_report, save_json_report, save_plot) — без изменений
