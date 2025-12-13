#!/usr/bin/env python3
"""
DiamondEye v6.7 — Professional HTTP Load Tester
"""
import asyncio
import time
import signal
import sys
from urllib.parse import urlparse
from datetime import datetime
import json

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
        if 'args' in globals():
            if args.debug:
                print(f"{Fore.RED}[DEBUG] Не удалось загрузить useragents: {e}{Style.RESET_ALL}")
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

    if args.http2 and args.extreme:
        print(f"{Fore.YELLOW}⚠️  --http2 отключён: несовместим с --extreme{Style.RESET_ALL}")

    if args.proxy and args.slow > 0:
        print(f"{Fore.YELLOW}⚠️  Прокси не работает с --slow (Slowloris){Style.RESET_ALL}")

    if args.flood:
        print(f"{Fore.RED}⚡ Внимание: --flood — высокая нагрузка на CPU{Style.RESET_ALL}")

    try:
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            print(f"{Fore.RED}❌ Некорректный URL{Style.RESET_ALL}")
            sys.exit(1)
    except Exception:
        print(f"{Fore.RED}❌ Ошибка URL{Style.RESET_ALL}")
        sys.exit(1)

    useragents = load_useragents(args.useragents) if args.useragents else []
    methods = parse_methods(args.methods)

    attack = DiamondEyeAttack(
        url=args.url,
        workers=args.workers,
        sockets=args.sockets,
        methods=methods,
        useragents=useragents,
        no_ssl_check=args.no_ssl_check,
        debug=args.debug,
        proxy=args.proxy,
        use_http2=args.use_http2,
        slow_rate=args.slow,
        extreme=args.extreme,
        data_size=args.data_size,
        flood=args.flood,
        path_fuzz=args.path_fuzz,
        header_flood=args.header_flood,
        method_fuzz=args.method_fuzz,
        args=args
    )

    monitor_task = None
    rps_task = None

    def signal_handler():
        if not attack._shutdown_event.is_set():
            print(f"\n{Fore.RED}🛑 Остановка...{Style.RESET_ALL}")
            attack._shutdown_event.set()
            if monitor_task: monitor_task.cancel()
            if rps_task: rps_task.cancel()

    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)
    except NotImplementedError:
        pass

    start_time = time.time()
    try:
        monitor_task = asyncio.create_task(attack.monitor())
        rps_task = asyncio.create_task(attack.collect_rps_stats())
        await attack.start()
    except asyncio.CancelledError:
        pass
    except Exception as e:
        if args.debug:
            print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
    finally:
        await attack.shutdown()
        attack.print_stats()
        print(f"\n{Fore.GREEN}✅ Атака завершена{Style.RESET_ALL}")

    if args.log:
        try:
            report = generate_report(attack, start_time, args)
            with open(args.log, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"{Fore.CYAN}📝 Отчёт: {args.log}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Ошибка лога: {e}{Style.RESET_ALL}")

    if args.json:
        try:
            save_json_report(attack, start_time, args, args.json)
            print(f"{Fore.CYAN}📦 JSON: {args.json}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ JSON ошибка: {e}{Style.RESET_ALL}")

    if args.plot:
        save_plot(attack, args.plot)


def generate_report(attack, start_time, args):
    duration = int(time.time() - start_time)
    total = attack.sent
    failed = attack.failed
    success_rate = ((total - failed) / total * 100) if total > 0 else 0
    rps = int(total / (duration or 1))

    return f"""╔════════════════════════════════════════════════╗
║           DIAMONDEYE v6.7 — ОТЧЁТ              ║
╚════════════════════════════════════════════════╝

🎯 Цель: {args.url}
⏱️  Время: {duration}с
⚡ Режим: {'Extreme' if args.extreme else 'Normal'}
🔁 Воркеры: {args.workers} | Сокетов: {args.sockets}
📊 Отправлено: {total:,}
🚀 Средний RPS: {rps:,}
📈 Успешность: {success_rate:.1f}%
⚠️  Ошибок: {failed}

════════════════════════════════════════════════
DiamondEye | by larion and Neo | v6.7
"""


def save_json_report(attack, start_time, args, filepath):
    duration = time.time() - start_time
    rps = int(attack.sent / (duration or 1))
    success_rate = ((attack.sent - attack.failed) / attack.sent * 100) if attack.sent > 0 else 0

    report = {
        "tool": "DiamondEye", "version": "6.7",
        "target": args.url, "duration_sec": int(duration),
        "config": {k: v for k, v in vars(args).items() if k not in ['func']},
        "metrics": {"sent": attack.sent, "failed": attack.failed, "rps": rps, "success_rate": success_rate}
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def save_plot(attack, filepath):
    if not MATPLOTLIB_AVAILABLE:
        print(f"{Fore.YELLOW}⚠️  matplotlib не установлен{Style.RESET_ALL}")
        return
    if not attack.rps_history:
        return
    try:
        times = [p['time'] for p in attack.rps_history]
        rps = [p['rps'] for p in attack.rps_history]
        plt.figure(figsize=(10, 5))
        plt.plot(times, rps, color='red')
        plt.xlabel('Время (с)')
        plt.ylabel('RPS')
        plt.title('RPS over time')
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(filepath)
        plt.close()
        print(f"{Fore.CYAN}📊 График: {filepath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ График: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Прервано.")
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка: {e}{Style.RESET_ALL}")
        sys.exit(1)
