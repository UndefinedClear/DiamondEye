# args.py
import argparse
import sys
from utils import parse_data_size

def validate_data_size(value):
    """Валидатор для размера данных."""
    size = parse_data_size(value)
    if size < 0:
        raise argparse.ArgumentTypeError("Invalid data size: use 1024, 64k, 1m")
    return size

def validate_port(value):
    """Валидатор для порта."""
    try:
        port = int(value)
        if 1 <= port <= 65535:
            return port
        raise argparse.ArgumentTypeError("Port must be between 1 and 65535")
    except ValueError:
        raise argparse.ArgumentTypeError("Port must be an integer")

def get_parser():
    """Создание парсера аргументов с только работающими флагами."""
    parser = argparse.ArgumentParser(
        description="DiamondEye v10.0 — Advanced Multi-Layer DDoS Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Layer7 Attack:  python main.py http://target.com --workers 100 --flood
  Layer4 Attack:  python main.py --attack-type tcp --target-ip 1.2.3.4 --target-port 80
  DNS Amplification: python main.py --attack-type dns --target-ip 1.2.3.4
  Adaptive Mode:  python main.py http://target.com --adaptive
  Reconnaissance: python main.py target.com --recon
  Plugin System:  python main.py --list-plugins
  Plugin Execution: python main.py http://target.com --plugin Slowloris
  
For detailed help on each option, use: python main.py --help
        """
    )
    
    # === ОСНОВНЫЕ ПАРАМЕТРЫ ===
    parser.add_argument('url', nargs='?', help='Target URL (e.g. http://127.0.0.1)')
    
    # === ТИП АТАКИ И ЦЕЛИ ===
    attack_group = parser.add_argument_group('Attack Configuration')
    attack_group.add_argument('--attack-type', 
                             choices=['http', 'tcp', 'dns', 'slowloris'],
                             default='http', help='Type of attack (default: http)')
    attack_group.add_argument('--target-ip', help='Target IP for Layer4/Amplification attacks')
    attack_group.add_argument('--target-port', type=validate_port, default=80, 
                             help='Target port for Layer4 attacks (default: 80)')
    attack_group.add_argument('--duration', type=int, default=0,
                             help='Attack duration in seconds (0 = unlimited)')
    
    # === ОГРАНИЧЕНИЯ (ПО УМОЛЧАНИЮ 0 = БЕЗ ЛИМИТОВ) ===
    limit_group = parser.add_argument_group('Rate Limiting (all disabled by default)')
    limit_group.add_argument('--max-rps', type=int, default=0,
                            help='Maximum requests per second (0 = unlimited, default: 0)')
    limit_group.add_argument('--max-bandwidth', type=float, default=0,
                            help='Maximum bandwidth in Mbps (0 = unlimited, default: 0)')
    
    # === LAYER7 (HTTP) ПАРАМЕТРЫ ===
    layer7_group = parser.add_argument_group('Layer7 (HTTP) Options')
    layer7_group.add_argument('--scan', action='store_true', help='Enable path scanning mode')
    layer7_group.add_argument('--wordlist', help='Custom wordlist file')
    layer7_group.add_argument('-t', '--threads', type=int, default=20, 
                             help='Scan threads (default: 20)')
    layer7_group.add_argument('-o', '--output', default="found.txt", 
                             help='Save found paths')
    
    layer7_group.add_argument('-w', '--workers', type=int, default=10, 
                             help='Number of worker tasks (default: 10)')
    layer7_group.add_argument('-s', '--sockets', type=int, default=100, 
                             help='Connections per worker (default: 100)')
    layer7_group.add_argument('-m', '--methods', 
                             help='GET,POST,PUT,PATCH,ALL (default: GET)')
    layer7_group.add_argument('-u', '--useragents', help='User-Agent file')
    layer7_group.add_argument('-n', '--no-ssl-check', action='store_true', 
                             help='Disable SSL certificate verification')
    layer7_group.add_argument('-d', '--debug', action='store_true', 
                             help='Enable debug mode')
    layer7_group.add_argument('-l', '--log', help='Save text report')
    layer7_group.add_argument('--json', help='Save JSON report')
    layer7_group.add_argument('--plot', help='Save RPS plot')
    
    # === ПРОКСИ ===
    proxy_group = parser.add_argument_group('Proxy Options')
    proxy_group.add_argument('--proxy', help='HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)')
    proxy_group.add_argument('--proxy-file', help='File with proxy list (one per line)')
    proxy_group.add_argument('--proxy-auto', action='store_true', 
                            help='Auto-fetch and rotate proxies')
    proxy_group.add_argument('--proxy-timeout', type=float, default=5.0,
                            help='Proxy check timeout in seconds (default: 5.0)')
    
    # === HTTP/2 И HTTP/3 ===
    http_group = parser.add_argument_group('HTTP Protocol Options')
    http_group.add_argument('--http2', action='store_true', help='Use HTTP/2')
    http_group.add_argument('--http3', action='store_true', 
                           help='Use HTTP/3 (QUIC) - requires additional dependencies')
    http_group.add_argument('--h2reset', action='store_true', 
                           help='Enable HTTP/2 Rapid Reset')
    
    # === ТЕХНИКИ АТАК ===
    tech_group = parser.add_argument_group('Attack Techniques')
    tech_group.add_argument('--websocket', action='store_true', 
                           help='WebSocket flood mode')
    tech_group.add_argument('--graphql-bomb', action='store_true', 
                           help='Send GraphQL batch bomb')
    tech_group.add_argument('--slow', type=float, default=0.0, 
                           help='Fraction of slow requests (0.0-1.0)')
    tech_group.add_argument('--extreme', action='store_true', 
                           help='New TCP connection per request')
    tech_group.add_argument('--flood', action='store_true', 
                           help='Minimal delay → max RPS')
    tech_group.add_argument('--data-size', type=validate_data_size, default=0, 
                           help='Body size (e.g. 1024, 64k, 1m)')
    
    # === ФАЗЗИНГ И ЗАПОЛНИТЕЛИ ===
    fuzz_group = parser.add_argument_group('Fuzzing & Evasion')
    fuzz_group.add_argument('--junk', action='store_true', 
                           help='Add random X-* headers')
    fuzz_group.add_argument('--random-host', action='store_true', 
                           help='Random subdomain in Host header')
    fuzz_group.add_argument('--path-fuzz', action='store_true', 
                           help='Random deep paths')
    fuzz_group.add_argument('--header-flood', action='store_true', 
                           help='Up to 20 junk headers')
    fuzz_group.add_argument('--method-fuzz', action='store_true', 
                           help='Use PROPFIND, REPORT, LOCK, etc.')
    fuzz_group.add_argument('--rotate-ua', action='store_true',
                           help='Rotate User-Agents automatically')
    
    # === АДАПТИВНЫЙ РЕЖИМ ===
    adaptive_group = parser.add_argument_group('Adaptive Mode')
    adaptive_group.add_argument('--adaptive', action='store_true', 
                               help='Adaptive RPS based on server response')
    
    # === АВТОРИЗАЦИЯ ===
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('--auth', help='Authorization token: Bearer <token>')
    
    # === СИСТЕМА ПЛАГИНОВ ===
    plugin_group = parser.add_argument_group('Plugin System')
    plugin_group.add_argument('--plugin', help='Execute specific plugin by name')
    plugin_group.add_argument('--list-plugins', action='store_true',
                             help='List all available plugins')
    plugin_group.add_argument('--plugin-config', help='Plugin configuration file (JSON)')
    plugin_group.add_argument('--disable-plugin-verification', action='store_true',
                             help='Disable plugin hash verification (dangerous)')
    
    # === СИСТЕМА РАЗВЕДКИ ===
    recon_group = parser.add_argument_group('Reconnaissance')
    recon_group.add_argument('--recon', action='store_true',
                            help='Perform reconnaissance on target')
    recon_group.add_argument('--recon-full', action='store_true',
                            help='Full reconnaissance with vulnerability scanning')
    recon_group.add_argument('--recon-ports', type=str, default='21-25,53,80,443,3306,3389,8080',
                            help='Ports to scan (comma-separated or range)')
    recon_group.add_argument('--recon-save', help='Save reconnaissance report to file')

    # === LAYER4 ПАРАМЕТРЫ (ТОЛЬКО РАБОЧИЕ) ===
    layer4_group = parser.add_argument_group('Layer4 Options')
    layer4_group.add_argument('--packet-size', type=int, default=1024,
                             help='Packet size for UDP floods (bytes)')
    layer4_group.add_argument('--spoof-ip', action='store_true',
                             help='Spoof source IP (requires root/admin)')
    
    # === МОНИТОРИНГ ===
    monitor_group = parser.add_argument_group('Monitoring')
    monitor_group.add_argument('--monitor-interval', type=float, default=1.0,
                             help='Stats update interval in seconds')
    monitor_group.add_argument('--resource-alert', type=int, default=90,
                             help='CPU/RAM usage alert threshold (percentage)')
    
    # === ЮРИДИЧЕСКОЕ ПРЕДУПРЕЖДЕНИЕ ===
    legal_group = parser.add_argument_group('Legal')
    legal_group.add_argument('--confirm-illegal', action='store_true',
                            help='Confirm understanding of legal implications for spoofing')
    legal_group.add_argument('--confirm-local', action='store_true',
                            help='Confirm attacking localhost')
    
    return parser

def parse_args():
    """Парсинг аргументов командной строки с валидацией."""
    parser = get_parser()
    
    # Если только --help или без аргументов, показываем помощь
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    
    args = parser.parse_args()
    
    # Валидация зависимых аргументов
    if args.http3:
        try:
            import httpx
            if not hasattr(httpx, 'HTTP3Transport'):
                print("⚠️  HTTP/3 support not detected. Install with: pip install 'httpx[http3]'")
                args.http3 = False
        except ImportError:
            print("⚠️  HTTP/3 not available. Install httpx with HTTP/3 support.")
            args.http3 = False
    
    if args.adaptive and args.extreme:
        print("⚠️  --adaptive and --extreme are incompatible. Disabling --extreme.")
        args.extreme = False
    
    if args.header_flood and not args.junk:
        print("⚠️  --header-flood requires --junk. Enabling --junk.")
        args.junk = True
    
    return args