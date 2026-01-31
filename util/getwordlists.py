#!/usr/bin/env python3
"""
DiamondEye — Wordlist Fetcher
Собирает актуальные списки путей с открытых источников
Сохраняет в папку wordlists/
Использование: python util/getwordlists.py
"""

import os
import sys
import asyncio
import aiohttp
import argparse
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re


# --- Настройки ---
OUTPUT_DIR = "wordlists"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Источники wordlist (URL -> категория)
SOURCES = {
    # Общие
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt": "common",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt": "quickhits",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/robotsdisallowed.txt": "robots",
    
    # Админ
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Admin%20Panels/common-admin-panels.txt": "admin",
    
    # Бэкапы
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Backup%20and%20Archives/common.txt": "backup",
    
    # CMS
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/WordPress.fuzz.txt": "wordpress",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/Joomla.txt": "joomla",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CMS/Drupal.fuzz.txt": "drupal",
    
    # CTF / Bug Bounty
    "https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/headers/paths.txt": "ctf_paths",
    "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/directory-traversal.txt": "traversal",
    
    # API / GraphQL
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/common-api-paths.txt": "api",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/api/paths.txt": "api",
    
    # Конфиги
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Config%20Files/.htaccess.txt": "config",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Config%20Files/.htpasswd.txt": "config",
    
    # Облачные
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/AWS.fuzz.txt": "aws",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/Git.fuzz.txt": "git",
}


# --- Функции ---
async def fetch_text(session, url):
    try:
        async with session.get(url, timeout=15) as resp:
            if resp.status == 200:
                return await resp.text()
    except Exception as e:
        print(f"❌ Ошибка загрузки {url}: {e}")
    return None


def clean_path(line):
    line = line.strip()
    if not line or line.startswith('#') or ' ' in line or len(line) > 100:
        return None
    if not line.startswith('/'):
        line = '/' + line
    return line


def extract_paths(content, source_url):
    paths = set()
    for line in content.splitlines():
        path = clean_path(line)
        if path:
            paths.add(path)
    return list(paths)


async def download_and_parse(session, url, category):
    content = await fetch_text(session, url)
    if not content:
        return []

    paths = extract_paths(content, url)
    print(f"✅ Загружено из {category}: {len(paths)} путей — {url}")
    return paths


async def main():
    parser = argparse.ArgumentParser(description="Сбор wordlist'ов для DiamondEye")
    parser.add_argument("--output", default=OUTPUT_DIR, help="Папка для сохранения (по умолчанию: wordlists/)")
    parser.add_argument("--all", action="store_true", help="Собрать всё (все источники)")
    parser.add_argument("--ctf", action="store_true", help="Только CTF/bug bounty")
    parser.add_argument("--admin", action="store_true", help="Только админ-пути")
    parser.add_argument("--api", action="store_true", help="Только API")
    args = parser.parse_args()

    # Фильтр источников
    filtered = SOURCES.copy()
    if args.ctf:
        filtered = {k: v for k, v in SOURCES.items() if v in ["ctf_paths", "common", "quickhits", "traversal"]}
    elif args.admin:
        filtered = {k: v for k, v in SOURCES.items() if "admin" in v}
    elif args.api:
        filtered = {k: v for k, v in SOURCES.items() if "api" in v}
    elif not args.all:
        print("⚠️  Укажите: --all, --ctf, --admin, --api")
        return

    connector = aiohttp.TCPConnector(limit=20, ssl=True)
    timeout = aiohttp.ClientTimeout(total=20)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = []
        for url, cat in filtered.items():
            tasks.append(download_and_parse(session, url, cat))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
    
    # Объединение
    all_paths = set()
    category_paths = {}
    
    for paths in results:
        if isinstance(paths, list):
            all_paths.update(paths)
            # Можно группировать по категории, если нужно

    # Сохранение
    combined_path = os.path.join(args.output, "combined.txt")
    with open(combined_path, "w", encoding="utf-8") as f:
        for path in sorted(all_paths):
            f.write(path + "\n")
    
    print(f"\n✅ Готово! Всего уникальных путей: {len(all_paths)}")
    print(f"💾 Сохранено: {combined_path}")

    # Сохранить отдельно (если нужно)
    # Можно добавить: --split — по категориям


if __name__ == "__main__":
    asyncio.run(main())
