#!/usr/bin/env python3
"""
DiamondEye — DNS Servers Fetcher
Собирает публичные DNS-серверы.
Сохраняет в wordlists/dns_servers.txt
"""

import os
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

DNS_SERVERS = [
    '8.8.8.8', '8.8.4.4',           # Google DNS
    '1.1.1.1', '1.0.0.1',           # Cloudflare
    '9.9.9.9', '149.112.112.112',   # Quad9
    '64.6.64.6', '64.6.65.6',       # Verisign
    '208.67.222.222', '208.67.220.220',  # OpenDNS
    '185.228.168.168',              # CleanBrowsing
    '76.76.19.19',                  # Alternate DNS
    '94.140.14.14', '94.140.15.15', # AdGuard
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    with open(os.path.join(args.output, "dns_servers.txt"), "w") as f:
        for ip in DNS_SERVERS:
            f.write(ip + "\n")

    print(f"✅ DNS servers saved: {len(DNS_SERVERS)}")

if __name__ == "__main__":
    main()