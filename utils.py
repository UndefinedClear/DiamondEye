import random
import string


def random_string(length: int) -> str:
    length = max(1, length)
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def parse_data_size(size_str: str) -> int:
    if not size_str or size_str.strip() == "0":
        return 0
    size_str = size_str.strip().lower()
    try:
        if size_str.endswith('k') or size_str.endswith('kb'):
            val = float(size_str[:-1].strip())
            return int(max(0, val * 1024))
        elif size_str.endswith('m') or size_str.endswith('mb'):
            val = float(size_str[:-1].strip())
            return int(max(0, val * 1024 * 1024))
        else:
            val = float(size_str)
            return int(max(0, val))
    except (ValueError, TypeError):
        return 0


def generate_headers(host: str, useragents: list, referers: list, use_junk: bool = False,
                     use_random_host: bool = False, header_flood: bool = False) -> dict:
    ua = random.choice(useragents) if useragents else "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    referer = random.choice(referers)

    headers = {
        'User-Agent': ua,
        'Referer': referer,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
    }

    if use_random_host:
        headers['Host'] = f"{random_string(8)}.{host}"
    else:
        headers['Host'] = host

    if use_junk:
        count = 20 if header_flood else random.randint(3, 8)
        for _ in range(count):
            headers[f'X-{random_string(random.randint(3, 12))}'] = random_string(random.randint(5, 20))

    return headers
