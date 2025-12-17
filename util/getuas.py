#!/usr/bin/env python3
"""
Скачивает список User-Agent с http://www.useragentstring.com/
Использование: python getuas.py "http://www.useragentstring.com/pages/Chrome/"
"""

import sys
import urllib.request
import urllib.error
from bs4 import BeautifulSoup


def fetch_user_agents(url: str) -> list:
    """Fetch and parse User-Agent strings from useragentstring.com"""
    if "useragentstring.com" not in url:
        print("❌ URL must be from http://www.useragentstring.com/")
        return []

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) DiamondEye/9.0"}
        )
        with urllib.request.urlopen(req, timeout=10) as f:
            if f.getcode() != 200:
                print(f"❌ HTTP {f.getcode()}")
                return []
            html_doc = f.read().decode('utf-8')

        soup = BeautifulSoup(html_doc, 'html.parser')
        liste = soup.find(id='liste')
        if not liste:
            print("❌ #liste not found. Structure changed?")
            return []

        uas = liste.find_all('li')
        if not uas:
            print("❌ No <li> elements found.")
            return []

        user_agents = []
        for ua in uas:
            ua_text = ua.get_text().strip()
            if ua_text:
                user_agents.append(ua_text)

        return user_agents

    except urllib.error.URLError as e:
        print(f"❌ Network error: {e}")
        return []
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return []


def main():
    if len(sys.argv) <= 1:
        print("❌ No URL specified. Usage: python getuas.py <URL>")
        sys.exit(1)

    url = sys.argv[1].strip()
    uas = fetch_user_agents(url)

    if not uas:
        print("❌ No User-Agents found. Check URL.")
        sys.exit(1)

    # Вывод в stdout
    for ua in uas:
        print(ua)

    print(f"\n✅ Found {len(uas)} User-Agent strings", file=sys.stderr)


if __name__ == "__main__":
    main()
