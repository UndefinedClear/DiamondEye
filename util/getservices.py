#!/usr/bin/env python3
"""
DiamondEye — Service Port Mapping Fetcher
Собирает соответствия порт -> сервис.
Сохраняет в wordlists/services.txt в формате порт:сервис
"""

import os
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

SERVICES = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPC', 135: 'MSRPC', 139: 'NetBIOS',
    143: 'IMAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 993: 'IMAPS',
    995: 'POP3S', 1723: 'PPTP', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL',
    5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt',
    27017: 'MongoDB', 9200: 'Elasticsearch'
}

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    with open(os.path.join(args.output, "services.txt"), "w") as f:
        for port, service in sorted(SERVICES.items()):
            f.write(f"{port}:{service}\n")

    print(f"✅ Services saved: {len(SERVICES)}")

if __name__ == "__main__":
    main()