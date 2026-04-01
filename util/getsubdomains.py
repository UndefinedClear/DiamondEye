#!/usr/bin/env python3
"""
DiamondEye — Subdomains Fetcher
Собирает популярные поддомены из SecLists.
Сохраняет в wordlists/subdomains.txt
"""

import os
import asyncio
import aiohttp
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BASE_SUBDOMAINS = ['www', 'mail', 'ftp', 'admin', 'webmail', 'server',
                   'ns1', 'ns2', 'cdn', 'api', 'blog', 'dev', 'test',
                   'staging', 'app', 'm', 'mobile', 'secure', 'portal']

GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
]

async def fetch_subdomains(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                subs = set()
                for line in text.splitlines():
                    line = line.strip().lower()
                    if line and not line.startswith('#'):
                        subs.add(line)
                return subs
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
    return set()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    subs = set(BASE_SUBDOMAINS)
    async with aiohttp.ClientSession() as session:
        for url in GITHUB_SOURCES:
            print(f"📡 Fetching {url}...")
            fetched = await fetch_subdomains(session, url)
            subs.update(fetched)
            await asyncio.sleep(0.5)

    with open(os.path.join(args.output, "subdomains.txt"), "w") as f:
        for sub in sorted(subs):
            f.write(sub + "\n")

    print(f"✅ Subdomains saved: {len(subs)}")

if __name__ == "__main__":
    asyncio.run(main())