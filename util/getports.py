#!/usr/bin/env python3
"""
DiamondEye — Common Ports Fetcher
Собирает популярные порты из SecLists.
Сохраняет в wordlists/common_ports.txt
"""

import os
import asyncio
import aiohttp
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BASE_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
              445, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Infrastructure/nmap-ports-top-1000.txt"
]

async def fetch_ports(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                ports = set()
                for line in text.splitlines():
                    line = line.strip()
                    if line and line.isdigit():
                        ports.add(int(line))
                return ports
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
    return set()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    ports = set(BASE_PORTS)
    async with aiohttp.ClientSession() as session:
        for url in GITHUB_SOURCES:
            print(f"📡 Fetching {url}...")
            fetched = await fetch_ports(session, url)
            ports.update(fetched)
            await asyncio.sleep(0.5)

    with open(os.path.join(args.output, "common_ports.txt"), "w") as f:
        for port in sorted(ports):
            f.write(str(port) + "\n")

    print(f"✅ Ports saved: {len(ports)}")

if __name__ == "__main__":
    asyncio.run(main())