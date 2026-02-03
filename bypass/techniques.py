# bypass/techniques.py
import random
import hashlib
import socket
import asyncio
import aiohttp
from typing import Dict, List, Optional
from urllib.parse import urlparse
from colorama import Fore, Style


class BypassTechniques:
    """Техники обхода WAF и систем защиты"""
    
    def __init__(self):
        self.cf_ips = []  # Кэш реальных IP за Cloudflare
        self.waf_detected = None
    
    @staticmethod
    def cloudflare_headers() -> Dict[str, str]:
        """Заголовки для обхода Cloudflare"""
        cf_connecting_ip = f"{random.randint(1,255)}.{random.randint(1,255)}." \
                          f"{random.randint(1,255)}.{random.randint(1,255)}"
        
        return {
            'CF-Connecting-IP': cf_connecting_ip,
            'X-Forwarded-For': cf_connecting_ip,
            'X-Real-IP': cf_connecting_ip,
            'True-Client-IP': cf_connecting_ip,
            'CF-RAY': hashlib.md5(str(random.random()).encode()).hexdigest()[:16],
            'CF-IPCountry': random.choice(['US', 'GB', 'DE', 'FR', 'JP']),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate, br',
            'Cache-Control': 'max-age=0',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Pragma': 'no-cache',
            'TE': 'trailers',
        }
    
    @staticmethod
    def ovh_bypass_headers() -> Dict[str, str]:
        """Заголовки для обхода OVH защиты"""
        return {
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Ssl': 'on',
            'X-Forwarded-Port': '443',
            'X-Forwarded-Host': random.choice(['localhost', '127.0.0.1', '0.0.0.0']),
            'X-Client-IP': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                          f"{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Originating-IP': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                               f"{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Remote-IP': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                          f"{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Remote-Addr': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                            f"{random.randint(1,255)}.{random.randint(1,255)}",
            'X-Proxy-IP': f"{random.randint(1,255)}.{random.randint(1,255)}." \
                         f"{random.randint(1,255)}.{random.randint(1,255)}",
        }
    
    @staticmethod
    def waf_bypass_headers() -> Dict[str, str]:
        """Общие заголовки для обхода WAF"""
        session_id = hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]
        
        return {
            'Cookie': f'PHPSESSID={session_id}; csrftoken={session_id[:16]}; sessionid={session_id}',
            'X-CSRFToken': session_id[:16],
            'X-Requested-With': 'XMLHttpRequest',
            'X-Ajax-Navigation': 'true',
            'X-Request-ID': session_id,
            'X-Correlation-ID': session_id[:24],
            'X-Debug': 'false',
            'X-Is-Ajax-Request': 'true',
            'X-PJAX': 'true',
            'X-PJAX-Container': '#main',
        }
    
    @staticmethod
    def generate_legit_session() -> Dict[str, str]:
        """Генерация легитной сессии"""
        session_id = hashlib.sha256(str(random.random()).encode()).hexdigest()[:32]
        csrf_token = hashlib.md5(str(random.random()).encode()).hexdigest()[:16]
        
        return {
            'Cookie': f'session={session_id}; _csrf={csrf_token}; auth_token={session_id[:24]}',
            'X-CSRF-Token': csrf_token,
            'X-XSRF-TOKEN': csrf_token,
            'X-Auth-Token': session_id[:24],
            'Authorization': f'Bearer {session_id}',
            'Referer': random.choice([
                'https://www.google.com/',
                'https://www.facebook.com/',
                'https://twitter.com/',
                'https://www.linkedin.com/'
            ]),
            'Origin': random.choice([
                'https://www.google.com',
                'https://www.facebook.com',
                'https://twitter.com',
                'https://www.linkedin.com'
            ]),
        }
    
    @staticmethod
    def rotate_user_agents() -> List[str]:
        """Список легитимных User-Agent"""
        return [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
            'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.144 Mobile Safari/537.36',
        ]