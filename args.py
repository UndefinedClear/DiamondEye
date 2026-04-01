#!/usr/bin/env python3
# args.py
import argparse
import sys

def parse_args():
    parser = argparse.ArgumentParser(
        description="DiamondEye v11.0 — Advanced Multi-Layer Security Testing Platform",
        epilog="Examples: python main.py https://target.com --workers 100 --flood\n"
               "          python main.py --recon target.com\n"
               "          python main.py --list-plugins",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("url", nargs="?", help="Target URL (for HTTP attacks)")
    parser.add_argument("--attack-type", default="http",
                        choices=["http", "tcp", "dns", "slowloris"],
                        help="Attack type (default: http)")
    parser.add_argument("--target-ip", help="Target IP address (for TCP/DNS)")
    parser.add_argument("--target-port", type=int, default=80,
                        help="Target port (default: 80)")
    parser.add_argument("-w", "--workers", type=int, default=10,
                        help="Number of worker processes")
    parser.add_argument("-s", "--sockets", type=int, default=100,
                        help="Number of sockets per worker")
    parser.add_argument("--duration", type=int, default=0,
                        help="Attack duration in seconds (0 = infinite)")

    parser.add_argument("-m", "--methods", default="GET",
                        help="HTTP methods comma separated (or 'ALL')")
    parser.add_argument("-u", "--useragents", help="User-Agent file path")
    parser.add_argument("-n", "--no-ssl-check", action="store_true",
                        help="Disable SSL certificate verification")
    parser.add_argument("--http2", action="store_true", help="Use HTTP/2")
    parser.add_argument("--http3", action="store_true", help="Use HTTP/3 (experimental)")
    parser.add_argument("--websocket", action="store_true", help="WebSocket flood")
    parser.add_argument("--flood", action="store_true",
                        help="Maximum RPS (no delays between requests)")
    parser.add_argument("--extreme", action="store_true",
                        help="New connection per request (high system load)")
    parser.add_argument("--slow", type=float, default=0.0,
                        help="Slow connection probability (0-1)")
    parser.add_argument("--adaptive", action="store_true",
                        help="Adaptive mode (auto load balancing)")
    parser.add_argument("--junk", action="store_true",
                        help="Add random HTTP headers")
    parser.add_argument("--header-flood", action="store_true",
                        help="Add up to 20 random headers (requires --junk)")
    parser.add_argument("--random-host", action="store_true",
                        help="Use random subdomains in Host header")
    parser.add_argument("--path-fuzz", action="store_true",
                        help="Deep random paths")
    parser.add_argument("--method-fuzz", action="store_true",
                        help="Use rare HTTP methods (PROPFIND, etc.)")
    parser.add_argument("--rotate-ua", action="store_true",
                        help="Rotate User-Agent (load from built-in list)")
    parser.add_argument("--auth", help="Bearer token for authorization")
    parser.add_argument("--h2reset", action="store_true",
                        help="HTTP/2 connection reset after request")
    parser.add_argument("--graphql-bomb", action="store_true",
                        help="GraphQL bomb (many requests to /graphql)")
    parser.add_argument("--data-size", type=int, default=0,
                        help="Request body size in bytes (for POST/PUT)")

    parser.add_argument("--pipeline", type=int, default=1,
                        help="HTTP pipelining depth (multiple requests per connection)")

    parser.add_argument("--max-rps", type=int, default=0,
                        help="Maximum requests per second")
    parser.add_argument("--max-bandwidth", type=float, default=0,
                        help="Maximum bandwidth in Mbps")

    parser.add_argument("--jitter", type=float, default=10.0,
                        help="Jitter percentage for pattern avoidance (0-100)")

    parser.add_argument("--proxy", help="Proxy URL (http://user:pass@host:port)")
    parser.add_argument("--proxy-file", help="File with proxy list")
    parser.add_argument("--proxy-auto", action="store_true",
                        help="Auto-fetch proxies from public sources")
    parser.add_argument("--proxy-timeout", type=float, default=5.0,
                        help="Proxy check timeout (seconds)")
    parser.add_argument("--spoof-ip", action="store_true",
                        help="IP spoofing (Layer4 only, requires root)")
    parser.add_argument("--interface", help="Network interface")
    parser.add_argument("--source-port", type=int, default=0,
                        help="Fixed source port (for TCP)")

    parser.add_argument("--auto-bypass", action="store_true",
                        help="Auto-detect and bypass WAF/CDN")

    parser.add_argument("--recon", action="store_true",
                        help="Reconnaissance mode")
    parser.add_argument("--all-ports", action="store_true",
                        help="Scan all 65535 ports (slow)")
    parser.add_argument("--recon-ports", help="Port ranges (e.g., 21-25,80,443)")
    parser.add_argument("--recon-save", help="Save report to file")
    
    parser.add_argument("--wayback", action="store_true",
                        help="Fetch historical URLs from Wayback Machine")
    parser.add_argument("--crt", action="store_true",
                        help="Fetch subdomains from certificate transparency logs")
    parser.add_argument("--syn-scan", action="store_true",
                        help="Use SYN scan for faster port scanning (requires root)")
    parser.add_argument("--scan-concurrency", type=int, default=500,
                        help="Concurrency for port scanning (default: 500)")
    parser.add_argument("--output-format", choices=["text", "json", "html"], default="text",
                        help="Report output format")

    parser.add_argument("--plugin", help="Run plugin by name")
    parser.add_argument("--list-plugins", action="store_true",
                        help="List available plugins")
    parser.add_argument("--add-plugin", help="Add new plugin from file (path relative to plugins/ or absolute)")
    parser.add_argument("--force-add", action="store_true", 
                        help="Auto-confirm plugin addition (skip warnings)")
    parser.add_argument("--plugin-config", help="Plugin config JSON file")
    parser.add_argument("--disable-plugin-verification", action="store_true",
                        help="Disable plugin hash verification")

    parser.add_argument("-l", "--log", help="Save text report")
    parser.add_argument("--json", help="Save JSON report")
    parser.add_argument("--plot", help="Save RPS graph (PNG)")
    parser.add_argument("--monitor-interval", type=float, default=1.0,
                        help="Resource monitoring interval (seconds)")
    parser.add_argument("--resource-alert", type=int, default=90,
                        help="CPU/RAM alert threshold (%%)")

    parser.add_argument("-d", "--debug", action="store_true",
                        help="Debug mode (verbose logs)")
    parser.add_argument("--packet-size", type=int, default=1024,
                        help="Packet size (for Layer4)")
    parser.add_argument("--ttl", type=int, default=64,
                        help="TTL for IP packets")
    parser.add_argument("--slow-connections", type=int, default=1000,
                        help="Maximum slow connections")
    parser.add_argument("--confirm-illegal", action="store_true",
                        help="Auto-confirm illegal techniques (e.g., spoofing)")
    parser.add_argument("--confirm-local", action="store_true",
                        help="Auto-confirm localhost attack")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)

    return parser.parse_args()