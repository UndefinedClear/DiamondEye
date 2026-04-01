# utils.py
import random
import string
import logging
from typing import List, Optional
from pathlib import Path

logger = logging.getLogger(__name__)

ROOT_DIR = Path(__file__).parent


def random_string(length: int, use_secrets: bool = False) -> str:
    length = max(1, length)
    if use_secrets:
        import secrets
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))


def load_useragents_from_file(filepath: str = None) -> List[str]:
    if filepath is None:
        filepath = ROOT_DIR / "res" / "lists" / "useragents" / "useragents.txt"
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            uas = [line.strip() for line in f if line.strip()]
            if uas:
                logger.info(f"Loaded {len(uas)} user agents from {filepath}")
                return uas
            else:
                logger.warning(f"User agent file {filepath} is empty")
                return []
    except Exception as e:
        logger.warning(f"Failed to load useragents from {filepath}: {e}")
        return []


def load_http_methods() -> list:
    methods_file = ROOT_DIR / "wordlists" / "http_methods.txt"
    try:
        with open(methods_file, 'r') as f:
            methods = [line.strip().upper() for line in f if line.strip()]
            if methods:
                return methods
    except Exception as e:
        logger.warning(f"Failed to load HTTP methods: {e}")
    return ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD']


def load_wordlist_paths(filepath: str = None) -> List[str]:
    if filepath is None:
        filepath = ROOT_DIR / "wordlists" / "combined.txt"
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            paths = [line.strip() for line in f if line.strip() and len(line) < 200]
            if paths:
                logger.info(f"Loaded {len(paths)} paths from {filepath}")
                return paths
            else:
                logger.warning(f"Wordlist file {filepath} is empty")
                return []
    except Exception as e:
        logger.warning(f"Failed to load wordlist from {filepath}: {e}")
        return []


def load_subdomains_list(filepath: str = None) -> List[str]:
    if filepath is None:
        filepath = ROOT_DIR / "wordlists" / "subdomains.txt"
    
    if not filepath.exists():
        try:
            paths = load_wordlist_paths()
            subs = [p.strip('/') for p in paths if p.count('/') == 1 and p[1:].isalnum()]
            if subs:
                logger.info(f"Generated {len(subs)} subdomains from wordlist")
                return subs[:500]
        except:
            pass
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            subs = [line.strip() for line in f if line.strip() and '.' not in line and '/' not in line]
            if subs:
                logger.info(f"Loaded {len(subs)} subdomains from {filepath}")
                return subs
    except Exception as e:
        logger.warning(f"Failed to load subdomains from {filepath}: {e}")
    
    return []