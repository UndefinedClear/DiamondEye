# bypass/header_generator.py
import random
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from utils import random_string


@dataclass
class HeaderConfig:
    """Configuration for header generation."""
    user_agents: List[str] = field(default_factory=list)
    referers: List[str] = field(default_factory=list)
    use_junk: bool = False
    use_random_host: bool = False
    header_flood: bool = False
    auth_token: Optional[str] = None
    randomize_order: bool = True
    extra_headers: Optional[Dict[str, str]] = None


class HeaderGenerator:
    """
    Generate HTTP headers with randomization.
    Supports order randomization and junk headers.
    """
    
    BASE_HEADERS = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.9',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Cache-Control': 'max-age=0',
    }
    
    def __init__(self, config: HeaderConfig):
        self.config = config
    
    def generate(self, host: str) -> Dict[str, str]:
        """
        Generate complete headers dict.
        
        Args:
            host: Target hostname
            
        Returns:
            Headers dictionary
        """
        headers = dict(self.BASE_HEADERS)
        
        ua = self._get_user_agent()
        headers['User-Agent'] = ua
        
        referer = self._get_referer()
        headers['Referer'] = referer
        
        if self.config.use_random_host:
            headers['Host'] = f"{random_string(8)}.{host}"
        else:
            headers['Host'] = host
        
        if self.config.auth_token:
            headers['Authorization'] = f"Bearer {self.config.auth_token}"
        
        if self.config.extra_headers:
            headers.update(self.config.extra_headers)
        
        if self.config.use_junk:
            count = 20 if self.config.header_flood else random.randint(3, 10)
            for _ in range(count):
                name = f"X-{random_string(random.randint(4, 15))}"
                value = random_string(random.randint(5, 25))
                headers[name] = value
        
        if self.config.randomize_order:
            headers = self._randomize_order(headers)
        
        return headers
    
    def _get_user_agent(self) -> str:
        if self.config.user_agents:
            return random.choice(self.config.user_agents)
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    
    def _get_referer(self) -> str:
        if self.config.referers:
            return random.choice(self.config.referers)
        return "https://www.google.com/"
    
    def _randomize_order(self, headers: Dict[str, str]) -> Dict[str, str]:
        items = list(headers.items())
        random.shuffle(items)
        return dict(items)