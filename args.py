# args.py
import argparse
from utils import parse_data_size


def validate_data_size(value):
    size = parse_data_size(value)
    if size < 0:
        raise argparse.ArgumentTypeError("Invalid data size: use 1024, 64k, 1m")
    return size


def parse_args():
    parser = argparse.ArgumentParser(description="DiamondEye v9.8 — BountyHunter Mode")
    parser.add_argument('url', help='Target URL (e.g. http://127.0.0.1)')
    
    #  Сканирование
    parser.add_argument('--scan', action='store_true', help='Enable path scanning mode')
    parser.add_argument('--wordlist', help='Custom wordlist file')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Scan threads (default: 20)')
    parser.add_argument('-o', '--output', default="found.txt", help='Save found paths (default: found.txt)')

    #  Базовые флаги настройки атаки
    parser.add_argument('-w', '--workers', type=int, default=10, help='Number of worker tasks')
    parser.add_argument('-s', '--sockets', type=int, default=100, help='Number of connections per worker')
    parser.add_argument('-m', '--methods', help='GET,POST,PUT,PATCH,ALL')
    parser.add_argument('-u', '--useragents', help='User-Agent file')
    parser.add_argument('-n', '--no-ssl-check', action='store_true')
    parser.add_argument('-d', '--debug', action='store_true')
    parser.add_argument('-l', '--log', help='Save text report')
    parser.add_argument('--json', help='Save JSON report')
    parser.add_argument('--plot', help='Save RPS plot (requires matplotlib)')

    # Флаги атаки
    parser.add_argument('--proxy', help='HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)')
    parser.add_argument('--http3', action='store_true', help='Use HTTP/3 (QUIC)')
    parser.add_argument('--websocket', action='store_true', help='WebSocket flood mode')
    parser.add_argument('--auth', help='Authorization token: Bearer <token>')
    parser.add_argument('--h2reset', action='store_true', help='Enable HTTP/2 Rapid Reset')
    parser.add_argument('--http2', action='store_true', help='Use HTTP/2 (not with --extreme)')
    parser.add_argument('--junk', action='store_true', help='Add random X-* headers')
    parser.add_argument('--random-host', action='store_true', help='Random subdomain in Host header')
    parser.add_argument('--slow', type=float, default=0.0, help='Fraction of slow requests (0.05 = 5%)')
    parser.add_argument('--extreme', action='store_true', help='New TCP connection per request')
    parser.add_argument('--data-size', type=validate_data_size, default=0, help='Body size: 64k, 1m')
    parser.add_argument('--flood', action='store_true', help='Minimal delay → max RPS')
    parser.add_argument('--path-fuzz', action='store_true', help='Random deep paths')
    parser.add_argument('--header-flood', action='store_true', help='Up to 20 junk headers')

    # Специфические флаги
    parser.add_argument('--graphql-bomb', action='store_true', help='Send GraphQL batch bomb')
    parser.add_argument('--adaptive', action='store_true', help='Adaptive RPS: increase until failure')
    parser.add_argument('--method-fuzz', action='store_true', help='Use PROPFIND, REPORT, LOCK')

    return parser.parse_args()
