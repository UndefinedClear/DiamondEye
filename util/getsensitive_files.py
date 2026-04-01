#!/usr/bin/env python3
"""
DiamondEye — Sensitive Files Fetcher
Собирает пути чувствительных файлов из SecLists.
Сохраняет в wordlists/sensitive_files.txt
"""

import os
import asyncio
import aiohttp
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "wordlists")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BASE_SENSITIVE = [
    '/.git/HEAD', '/.env', '/.htaccess', '/.htpasswd',
    '/wp-config.php', '/config.php', '/configuration.php',
    '/phpinfo.php', '/info.php', '/test.php',
    '/backup.sql', '/dump.sql', '/db.sql',
    '/robots.txt', '/sitemap.xml', '/crossdomain.xml',
    '/server-status', '/server-info', '/phpmyadmin/',
    '/web.config', '/.well-known/security.txt',
    '/.aws/credentials', '/.azure/accessTokens.json', '/.gcloud/credentials'
]

GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Common-DB-Backups.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Config-Files.txt",
]

async def fetch_paths(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status == 200:
                text = await resp.text()
                paths = set()
                for line in text.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not line.startswith('/'):
                            line = '/' + line
                        paths.add(line)
                return paths
    except Exception as e:
        print(f"❌ Error fetching {url}: {e}")
    return set()

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=OUTPUT_DIR)
    args = parser.parse_args()

    paths = set(BASE_SENSITIVE)
    async with aiohttp.ClientSession() as session:
        for url in GITHUB_SOURCES:
            print(f"📡 Fetching {url}...")
            fetched = await fetch_paths(session, url)
            paths.update(fetched)
            await asyncio.sleep(0.5)

    with open(os.path.join(args.output, "sensitive_files.txt"), "w") as f:
        for p in sorted(paths):
            f.write(p + "\n")

    print(f"✅ Sensitive files saved: {len(paths)}")

if __name__ == "__main__":
    asyncio.run(main())