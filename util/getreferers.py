#!/usr/bin/env python3
"""
DiamondEye — Referer Fetcher
Собирает популярные HTTP Referer.
Сохраняет в wordlists/referers.txt
"""

import os
import asyncio
import aiohttp
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "referers.txt")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BASE_REFERERS = [
    'http://google.com/',
    'http://bing.com/',
    'http://yahoo.com/',
    'http://duckduckgo.com/',
    'http://facebook.com/',
    'http://twitter.com/',
    'http://linkedin.com/',
    'http://yandex.ru/',
    'http://baidu.com/',
    'http://reddit.com/',
    'http://pinterest.com/',
    'http://tumblr.com/',
    'http://instagram.com/',
    'http://youtube.com/',
    'http://wikipedia.org/',
]

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    referers = set(BASE_REFERERS)

    # Сохраняем
    with open(os.path.join(args.output, "referers.txt"), "w") as f:
        for ref in sorted(referers):
            f.write(ref + "\n")

    print(f"✅ Referers saved: {len(referers)}")
    print(f"💾 {os.path.join(args.output, 'referers.txt')}")

if __name__ == "__main__":
    asyncio.run(main())