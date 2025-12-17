# scanner.py — DiamondEye BountyHunter Scanner
import asyncio
import aiohttp
import random
import os
import sys
from urllib.parse import urljoin, urlparse
from colorama import Fore, Style


WORDLIST_DIR = "wordlists"
DEFAULT_WORDLIST_FILE = os.path.join(WORDLIST_DIR, "combined.txt")


def load_wordlists() -> list:
    """Загружает все .txt файлы из wordlists/ или combined.txt"""
    paths = set()

    # Попробуем загрузить combined.txt
    if os.path.exists(DEFAULT_WORDLIST_FILE):
        try:
            with open(DEFAULT_WORDLIST_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if not line.startswith('/'):
                            line = '/' + line
                        paths.add(line)
            print(f"{Fore.CYAN}📁 Загружено {len(paths)} путей из {DEFAULT_WORDLIST_FILE}{Style.RESET_ALL}")
            return sorted(paths)
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  Не удалось прочитать {DEFAULT_WORDLIST_FILE}: {e}{Style.RESET_ALL}")

    # Если combined.txt нет — ищем все .txt в папке
    if os.path.exists(WORDLIST_DIR) and os.path.isdir(WORDLIST_DIR):
        txt_files = [f for f in os.listdir(WORDLIST_DIR) if f.endswith('.txt')]
        if not txt_files:
            print(f"{Fore.RED}❌ В папке {WORDLIST_DIR} нет .txt файлов{Style.RESET_ALL}")
            return []

        for fname in txt_files:
            fpath = os.path.join(WORDLIST_DIR, fname)
            try:
                with open(fpath, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            if not line.startswith('/'):
                                line = '/' + line
                            paths.add(line)
            except Exception as e:
                print(f"{Fore.YELLOW}⚠️  Ошибка чтения {fname}: {e}{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}❌ Папка {WORDLIST_DIR} не найдена{Style.RESET_ALL}")
        return []

    print(f"{Fore.CYAN}📁 Загружено {len(paths)} уникальных путей из {WORDLIST_DIR}/{Style.RESET_ALL}")
    return sorted(paths)


async def fetch(session, url, sem, target_domain, tasks, results):
    async with sem:
        try:
            async with session.get(url, allow_redirects=True, timeout=8) as resp:
                if resp.status in (200, 301, 302, 403):
                    redirect = str(resp.headers.get("Location", ""))
                    status_line = f"{Fore.GREEN}[{resp.status}]" if resp.status == 200 else f"{Fore.YELLOW}[{resp.status}]"
                    print(f"{status_line} {url} {Fore.CYAN}{redirect}{Style.RESET_ALL}")

                    # Если 301/302 и редирект внутри домена — добавляем в сканирование
                    if resp.status in (301, 302) and redirect and target_domain in redirect:
                        if not any(t.get_coro().__name__ == 'fetch' and str(t) == str(url) for t in tasks):
                            task = asyncio.create_task(
                                fetch(session, redirect, sem, target_domain, tasks, results)
                            )
                            tasks.append(task)

                    results.append({
                        "url": url,
                        "status": resp.status,
                        "redirect": redirect
                    })
        except Exception as e:
            pass


async def start_scan(target: str, wordlist_path: str = None, threads: int = 20, output: str = "found.txt"):
    if not target.startswith("http"):
        target = "https://" + target

    parsed = urlparse(target)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    target_domain = parsed.netloc

    # Загружаем пути
    if wordlist_path and os.path.exists(wordlist_path):
        # Если указан кастомный файл — используем его
        try:
            with open(wordlist_path, 'r', encoding='utf-8') as f:
                raw = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                paths = list(set(p if p.startswith('/') else '/' + p for p in raw))
            print(f"{Fore.CYAN}📁 Загружено {len(paths)} путей из {wordlist_path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Не удалось загрузить {wordlist_path}: {e}{Style.RESET_ALL}")
            return
    else:
        # Используем wordlists/ из папки
        paths = load_wordlists()
        if not paths:
            print(f"{Fore.RED}❌ Нет доступных путей для сканирования{Style.RESET_ALL}")
            return

    print(f"{Fore.CYAN}🚀 Сканируем: {target} | Путей: {len(paths)} | Потоков: {threads}{Style.RESET_ALL}")

    connector = aiohttp.TCPConnector(ssl=False, limit=100, enable_cleanup_closed=True)
    session = aiohttp.ClientSession(
        connector=connector,
        headers={
            "User-Agent": random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "keep-alive"
        },
        timeout=aiohttp.ClientTimeout(total=10)
    )

    sem = asyncio.Semaphore(threads)
    tasks = []
    results = []

    for path in paths:
        url = urljoin(base_url, path.strip())
        task = asyncio.create_task(fetch(session, url, sem, target_domain, tasks, results))
        tasks.append(task)

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}🛑 Сканирование прервано{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
    finally:
        await session.close()

    if results and output:
        try:
            with open(output, 'w', encoding='utf-8') as f:
                for r in results:
                    f.write(f"{r['status']} {r['url']} {r['redirect']}\n")
            print(f"{Fore.CYAN}💾 Результаты сохранены: {output}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}❌ Не удалось сохранить: {e}{Style.RESET_ALL}")

    print(f"{Fore.GREEN}✅ Сканирование завершено: найдено {len(results)} путей{Style.RESET_ALL}")
