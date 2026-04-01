#!/usr/bin/env python3
"""
DiamondEye — Proxy Sources Fetcher
Собирает URL источников прокси.
Сохраняет в wordlists/proxy_sources.txt
"""

import os
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks4.txt",
    "https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks4.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks4.txt",
    "https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt",
]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    with open(os.path.join(args.output, "proxy_sources.txt"), "w") as f:
        for url in PROXY_SOURCES:
            f.write(url + "\n")

    print(f"✅ Proxy sources saved: {len(PROXY_SOURCES)}")

if __name__ == "__main__":
    main()