#!/usr/bin/env python3
"""
DiamondEye — User-Agent Fetcher
Собирает User-Agent'ы с useragentstring.com (все страницы) + GitHub
Сохраняет в один файл, удаляет дубликаты
Использование: python util/getuas.py
"""

import sys
import os
import json
import urllib.request
import urllib.error
from bs4 import BeautifulSoup
import time

# --- Настройки ---
current_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(current_dir, "..", "res", "lists", "useragents")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "useragents.txt")
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Цвета для вывода
GREEN = '\033[92m'
CYAN = '\033[96m'
YELLOW = '\033[93m'
RED = '\033[91m'
RESET = '\033[0m'

# ========== ИСТОЧНИКИ ==========

# 1. UserAgentString.com — все страницы (ОРИГИНАЛЬНЫЙ МЕТОД)
UA_PAGES = [
    "http://www.useragentstring.com/pages/Chrome/",
    "http://www.useragentstring.com/pages/Firefox/",
    "http://www.useragentstring.com/pages/Safari/",
    "http://www.useragentstring.com/pages/Internet%20Explorer/",
    "http://www.useragentstring.com/pages/Opera/",
    "http://www.useragentstring.com/pages/Edge/",
    "http://www.useragentstring.com/pages/Mobile/",
    "http://www.useragentstring.com/pages/Android%20Webkit%20Browser/",
    "http://www.useragentstring.com/pages/iPhone/",
    "http://www.useragentstring.com/pages/iPad/",
    "http://www.useragentstring.com/pages/Blackberry/",
    "http://www.useragentstring.com/pages/Googlebot/",
    "http://www.useragentstring.com/pages/Bingbot/",
    "http://www.useragentstring.com/pages/YandexBot/",
    "http://www.useragentstring.com/pages/Slurp/",
    "http://www.useragentstring.com/pages/DuckDuckBot/",
    "http://www.useragentstring.com/pages/Baiduspider/",
    "http://www.useragentstring.com/pages/Netscape/",
    "http://www.useragentstring.com/pages/Mosaic/",
    "http://www.useragentstring.com/pages/Lynx/",
    "http://www.useragentstring.com/pages/All/",  # ВСЕ В ОДНОМ
]

# 2. GitHub источники (ДОПОЛНИТЕЛЬНО)
GITHUB_SOURCES = [
    "https://raw.githubusercontent.com/fake-useragent/fake-useragent/master/src/fake_useragent/data/browsers.json",
    "https://raw.githubusercontent.com/microlinkhq/top-user-agents/master/index.json",
    "https://raw.githubusercontent.com/monperrus/crawler-user-agents/master/crawler-user-agents.json",
    "https://raw.githubusercontent.com/iamdarkme/User-Agents/main/user-agents.txt",
    "https://raw.githubusercontent.com/iamdarkme/User-Agents/main/browsers.txt",
    "https://raw.githubusercontent.com/iamdarkme/User-Agents/main/mobile.txt",
]

# ========== ОРИГИНАЛЬНАЯ ФУНКЦИЯ (НЕ ТРОГАЕМ) ==========

def fetch_user_agents_original(url: str) -> list:
    """
    ОРИГИНАЛЬНАЯ функция из getuas.py
    Fetch and parse User-Agent strings from useragentstring.com
    """
    if "useragentstring.com" not in url:
        print(f"{RED}❌ URL must be from http://www.useragentstring.com/{RESET}")
        return []

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) DiamondEye/9.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as f:
            if f.getcode() != 200:
                print(f"{RED}❌ HTTP {f.getcode()}{RESET}")
                return []
            html_doc = f.read().decode('utf-8')

        soup = BeautifulSoup(html_doc, 'html.parser')
        liste = soup.find(id='liste')
        if not liste:
            print(f"{YELLOW}⚠️  #liste not found. Structure changed?{RESET}")
            return []

        uas = liste.find_all('li')
        if not uas:
            print(f"{YELLOW}⚠️  No <li> elements found.{RESET}")
            return []

        user_agents = []
        for ua in uas:
            ua_text = ua.get_text().strip()
            if ua_text:
                user_agents.append(ua_text)

        return user_agents

    except urllib.error.URLError as e:
        print(f"{RED}❌ Network error: {e}{RESET}")
        return []
    except Exception as e:
        print(f"{RED}❌ Unexpected error: {e}{RESET}")
        return []

# ========== ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ ==========

def fetch_from_github(url: str, ua_set: set) -> int:
    """Сбор с GitHub raw файлов"""
    try:
        path = url.split('/')[-1]
        print(f"{CYAN}📡 GitHub: {path}...{RESET}", end="", flush=True)
        
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) DiamondEye/9.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as f:
            if f.getcode() != 200:
                print(f"{RED} ✗ HTTP {f.getcode()}{RESET}")
                return 0
            content = f.read().decode('utf-8')
        
        count = 0
        
        # Пробуем как JSON
        try:
            data = json.loads(content)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        for key in ['ua', 'user_agent', 'pattern', 'useragent']:
                            if key in item and isinstance(item[key], str):
                                if item[key] not in ua_set:
                                    ua_set.add(item[key])
                                    count += 1
                    elif isinstance(item, str):
                        if item not in ua_set:
                            ua_set.add(item)
                            count += 1
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, dict) and 'useragent' in item:
                                if item['useragent'] not in ua_set:
                                    ua_set.add(item['useragent'])
                                    count += 1
                            elif isinstance(item, str):
                                if item not in ua_set:
                                    ua_set.add(item)
                                    count += 1
        except:
            # Не JSON — читаем построчно
            for line in content.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    line = line.strip('",\'')
                    if len(line) > 20 and line not in ua_set:
                        ua_set.add(line)
                        count += 1
        
        print(f"{GREEN} ✓ +{count}{RESET}")
        return count
        
    except Exception as e:
        print(f"{RED} ✗ Error: {e}{RESET}")
        return 0

# ========== ГЛАВНАЯ ФУНКЦИЯ ==========

def main():
    print(f"{CYAN}╔══════════════════════════════════════════════════════════╗{RESET}")
    print(f"{CYAN}║         DiamondEye User-Agent Fetcher (MEGA)            ║{RESET}")
    print(f"{CYAN}║     Оригинальный метод + дополнительные источники       ║{RESET}")
    print(f"{CYAN}╚══════════════════════════════════════════════════════════╝{RESET}")
    print()
    
    all_uas = set()
    
    # ===== 1. Сбор с useragentstring.com (ОРИГИНАЛЬНЫЙ МЕТОД) =====
    print(f"{YELLOW}🔍 Сбор с useragentstring.com ({len(UA_PAGES)} страниц){RESET}")
    print(f"{CYAN}{'='*50}{RESET}")
    
    for page_url in UA_PAGES:
        browser_name = page_url.split('/')[-2]
        print(f"{CYAN}📡 {browser_name}...{RESET}", end="", flush=True)
        
        uas = fetch_user_agents_original(page_url)
        before = len(all_uas)
        all_uas.update(uas)
        new_count = len(all_uas) - before
        
        if new_count > 0:
            print(f"{GREEN} ✓ +{new_count}{RESET}")
        else:
            print(f"{YELLOW} ⚠️ 0 новых{RESET}")
        
        time.sleep(0.3)  # Задержка чтобы не забанили
    
    # ===== 2. Дополнительный сбор с GitHub =====
    print(f"\n{YELLOW}🔍 Дополнительный сбор с GitHub ({len(GITHUB_SOURCES)} источников){RESET}")
    print(f"{CYAN}{'='*50}{RESET}")
    
    for url in GITHUB_SOURCES:
        fetch_from_github(url, all_uas)
        time.sleep(0.1)
    
    # ===== 3. Сохранение =====
    uas_list = sorted(all_uas)
    
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for ua in uas_list:
            f.write(ua + '\n')
    
    print(f"\n{GREEN}{'='*60}{RESET}")
    print(f"{GREEN}✅ ГОТОВО!{RESET}")
    print(f"{CYAN}📁 Файл: {OUTPUT_FILE}{RESET}")
    print(f"{CYAN}🔢 Уникальных User-Agent'ов: {len(uas_list)}{RESET}")
    
    # Статистика
    if uas_list:
        lengths = [len(ua) for ua in uas_list]
        print(f"{CYAN}📊 Статистика:{RESET}")
        print(f"  Минимальная длина: {min(lengths)}")
        print(f"  Максимальная длина: {max(lengths)}")
        print(f"  Средняя длина: {sum(lengths)/len(lengths):.0f}")
    
    # Примеры
    print(f"\n{CYAN}📋 Примеры (первые 5):{RESET}")
    for i, ua in enumerate(uas_list[:5], 1):
        if len(ua) > 100:
            print(f"  {i}. {ua[:100]}...")
        else:
            print(f"  {i}. {ua}")
    
    print(f"\n{CYAN}💡 Использование в атаке:{RESET}")
    print(f"  python main.py http://target.com --rotate-ua --useragents {OUTPUT_FILE}")
    print(f"{GREEN}{'='*60}{RESET}")

if __name__ == "__main__":
    main()