# utils.py
import random
import string
import logging
from typing import List, Optional

# Настройка логгера для модуля
logger = logging.getLogger(__name__)

def random_string(length: int, use_secrets: bool = False) -> str:
    """
    Генерация случайной строки заданной длины.
    Если use_secrets=True, используется криптостойкий генератор (для токенов).
    """
    length = max(1, length)
    if use_secrets:
        import secrets
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def parse_data_size(size_str: str) -> int:
    """Преобразование строки размера (например '10k', '2m') в байты."""
    if not size_str or size_str.strip() == "0":
        return 0
    size_str = size_str.strip().lower()
    try:
        if size_str.endswith(('k', 'kb')):
            val = float(size_str.rstrip('kb').strip())
            return int(max(0, val * 1024))
        elif size_str.endswith(('m', 'mb')):
            val = float(size_str.rstrip('mb').strip())
            return int(max(0, val * 1024 * 1024))
        else:
            val = float(size_str)
            return int(max(0, val))
    except (ValueError, TypeError) as e:
        logger.error(f"Invalid data size: {size_str} - {e}")
        return 0


def generate_headers(host: str, useragents: List[str], referers: List[str],
                     use_junk: bool = False, use_random_host: bool = False,
                     header_flood: bool = False, auth_token: str = None) -> dict:
    """Генерация HTTP-заголовков для запроса."""
    ua = random.choice(useragents) if useragents else "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    referer = random.choice(referers) if referers else "http://google.com/"

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

    if auth_token:
        headers['Authorization'] = f"Bearer {auth_token}"

    if use_junk:
        count = 20 if header_flood else random.randint(3, 8)
        for _ in range(count):
            headers[f'X-{random_string(random.randint(3, 12))}'] = random_string(random.randint(5, 20))

    return headers


class DataPool:
    """
    Пул предварительно сгенерированных данных для тела запроса.
    Позволяет избежать генерации на каждый запрос.
    """
    def __init__(self, data_size: int, pool_size: int = 100):
        self.data_size = data_size
        self.pool_size = pool_size
        self._pool: List[str] = []
        self._generate()

    def _generate(self):
        for _ in range(self.pool_size):
            if random.random() < 0.5:
                # JSON-подобный payload
                payload_size = max(1, self.data_size - 15)
                data = f'{{"d": "{random_string(payload_size)}"}}'
            else:
                data = 'X' * self.data_size
            self._pool.append(data)

    def get_random(self) -> str:
        return random.choice(self._pool)