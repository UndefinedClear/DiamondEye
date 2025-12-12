#!/usr/bin/env python3
"""
DiamondEye v6.7 — Professional HTTP Load Tester
"""
import asyncio
import time
import signal
import sys
import json
from urllib.parse import urlparse
from datetime import datetime
from typing import List, Dict

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from args import parse_args
from attack import GoldenEyeAttack
from colorama import Fore, Style


def load_useragents(filepath: str) -> List[str]:
    """Загружает User-Agent'ы из файла."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        if 'args' in globals():
            if args.debug:
                print(f"{Fore.RED}[DEBUG] Не удалось загрузить useragents: {e}{Style.RESET_ALL}")
        return []


def parse_methods(raw: str) -> List[str]:
    """Парсит методы из строки."""
    ALL_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS', 'HEAD']
    if not raw:
        return ['GET']
    if raw.upper() == 'ALL':
        return ALL_METHODS
    return [m.strip().upper() for m in raw.split(',') if m.strip().upper() in ALL_METHODS]


async def main():
    args = parse_args()

    # Проверка URL
    try:
        parsed = urlparse(args.url)
        if not parsed.scheme or not parsed.netloc:
            print(f"{Fore.RED}❌ Некорректный URL: {args.url}{Style.RESET_ALL}")
            sys.exit(1)
    except Exception:
        print(f"{Fore.RED}❌ Ошибка разбора URL.{Style.RESET_ALL}")
        sys.exit(1)

    # Загрузка User-Agent'ов
    useragents = load_useragents(args.useragents) if args.useragents else []

    # Парсинг методов
    methods = parse_methods(args.methods)

    # Создание атаки
    attack = GoldenEyeAttack(
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

    # Задачи мониторинга
    monitor_task = None
    rps_task = None

    def signal_handler():
        if not attack._shutdown_event.is_set():
            print(f"\n{Fore.RED}🛑 Принудительная остановка атаки...{Style.RESET_ALL}")
            attack._shutdown_event.set()  # Сигнал всем воркерам
            if monitor_task:
                monitor_task.cancel()
            if rps_task:
                rps_task.cancel()

    # Регистрация обработчиков сигналов
    try:
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGINT, signal_handler)
        loop.add_signal_handler(signal.SIGTERM, signal_handler)
    except NotImplementedError:
        pass  # Windows

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
        print(f"\n{Fore.GREEN}✅ Атака остановлена корректно{Style.RESET_ALL}")

    # Генерация отчётов
    end_time = time.time()
    if args.log:
        try:
            report = generate_report(attack, start_time, end_time, args)
            with open(args.log, 'w', encoding='utf-8') as f:
                f.write(report)
            print(f"{Fore.CYAN}📝 Отчёт сохранён: {args.log}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Ошибка сохранения лога: {e}{Style.RESET_ALL}")

    if args.json:
        try:
            save_json_report(attack, start_time, end_time, args, args.json)
            print(f"{Fore.CYAN}📦 JSON-отчёт сохранён: {args.json}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Ошибка сохранения JSON: {e}{Style.RESET_ALL}")

    if args.plot:
        save_plot(attack, args.plot)


def generate_report(attack, start_time, end_time, args):
    """Генерация текстового отчёта."""
    duration = int(end_time - start_time)
    total = attack.sent
    failed = attack.failed
    success_rate = ((total - failed) / total * 100) if total > 0 else 0
    rps = int(total / (duration or 1))
    latency_increase = attack.get_avg_latency_increase()
    status = "🟢 Низкая нагрузка" if rps < 100 else "🟡 Средняя нагрузка" if rps < 500 else "🔴 Высокая нагрузка"
    down_status = "✅ Сервер в сети" if not attack.was_server_down() else "❌ Сервер НЕДОСТУПЕН"

    return f"""╔════════════════════════════════════════════════╗
║           DIAMONDEYE v6.7 — ОТЧЁТ ОБ АТАКЕ         ║
╚════════════════════════════════════════════════╝

🎯 Цель: {args.url}
⏱️  Продолжительность: {duration} сек
👥 Воркеры: {args.workers} | Сокетов: {args.sockets}
📌 Методы: {','.join(attack.methods)}
📶 HTTP/2: {'Да' if args.http2 else 'Нет'}
🧩 Junk: {'Да' if args.junk else 'Нет'}
🏠 Random Host: {'Да' if args.random_host else 'Нет'}
⚡ Режим: {'Extreme' if args.extreme else 'Normal'}
🔁 Отправлено: {total:,}
🚀 Средний RPS: {rps:,}
📈 Успешность: {success_rate:.1f}%
⏱️  Баз. задержка: {attack.base_latency:.2f} мс
⏫ Увеличение: {latency_increase:.1f}%
📊 Нагрузка: {status}
📡 Состояние: {down_status}

📝 Примечания:
   • Атака остановлена вручную
   • Все заголовки и параметры — случайные
   • Режим: {'HTTP/2 + Junk + Flood' if args.http2 and args.junk and args.flood else 'Стандартный'}

════════════════════════════════════════════════
DiamondEye — Enhanced Load Tester | by larion
v6.7 — method_fuzz, extreme/http2 fix, slow_request, path-fuzz
"""


def save_json_report(attack, start_time, end_time, args, filepath: str):
    """Сохранение JSON-отчёта."""
    duration = end_time - start_time
    rps = int(attack.sent / (duration or 1))
    success_rate = ((attack.sent - attack.failed) / attack.sent * 100) if attack.sent > 0 else 0

    report = {
        "tool": "DiamondEye",
        "version": "6.7",
        "target": args.url,
        "start_time": datetime.fromtimestamp(start_time).isoformat(),
        "end_time": datetime.fromtimestamp(end_time).isoformat(),
        "duration_sec": round(duration),
        "config": {
            "workers": args.workers,
            "sockets_per_worker": args.sockets,
            "methods": attack.methods,
            "http2": args.http2,
            "junk": args.junk,
            "random_host": args.random_host,
            "slow_rate": args.slow,
            "extreme": args.extreme,
            "flood": args.flood,
            "data_size": args.data_size,
            "path_fuzz": args.path_fuzz,
            "header_flood": args.header_flood,
            "method_fuzz": args.method_fuzz
        },
        "metrics": {
            "requests_sent": attack.sent,
            "requests_failed": attack.failed,
            "success_rate": round(success_rate, 2),
            "avg_rps": rps,
            "server_down": attack.was_server_down()
        },
        "rps_history": attack.rps_history
    }
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def save_plot(attack, filepath: str):
    """Сохранение графика RPS."""
    if not MATPLOTLIB_AVAILABLE:
        print(f"{Fore.YELLOW}⚠️  matplotlib не установлен. График не создан.{Style.RESET_ALL}")
        return
    if not attack.rps_history:
        print(f"{Fore.YELLOW}⚠️  Нет данных для графика.{Style.RESET_ALL}")
        return
    try:
        times = [p['time'] for p in attack.rps_history]
        rps = [p['rps'] for p in attack.rps_history]
        plt.figure(figsize=(10, 5))
        plt.plot(times, rps, label='RPS', color='tab:red')
        plt.xlabel('Время (сек)')
        plt.ylabel('Запросов в секунду')
        plt.title(f'Нагрузка — {attack.url}')
        plt.grid(True, alpha=0.3)
        plt.legend()
        plt.tight_layout()
        plt.savefig(filepath)
        plt.close()
        print(f"{Fore.CYAN}📊 График RPS сохранён: {filepath}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Ошибка графика: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Атака прервана.")
    except Exception as e:
        print(f"{Fore.RED}❌ Критическая ошибка: {e}{Style.RESET_ALL}")
        sys.exit(1)
