# recon/wayback.py
import asyncio
import aiohttp
from typing import List, Set, Optional
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class WaybackMachine:
    """
    Fetch historical URLs from Wayback Machine.
    """
    
    API_URL = "https://web.archive.org/cdx/search/cdx"
    
    def __init__(self, domain: str):
        self.domain = domain
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def fetch_urls(self, limit: int = 1000) -> Set[str]:
        """
        Fetch historical URLs for domain.
        
        Args:
            limit: Maximum number of URLs to return
            
        Returns:
            Set of unique URLs
        """
        urls = set()
        
        params = {
            "url": f"{self.domain}/*",
            "output": "json",
            "fl": "original",
            "collapse": "urlkey",
            "limit": limit
        }
        
        try:
            session = await self._get_session()
            async with session.get(self.API_URL, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    # Skip first line (header)
                    for row in data[1:]:
                        if row and row[0]:
                            urls.add(row[0])
                    logger.info(f"Fetched {len(urls)} historical URLs from Wayback")
                else:
                    logger.warning(f"Wayback API returned {resp.status}")
                    
        except Exception as e:
            logger.error(f"Failed to fetch from Wayback: {e}")
        
        return urls
    
    async def fetch_paths(self, limit: int = 1000) -> Set[str]:
        """
        Fetch only paths (without domain).
        
        Returns:
            Set of unique paths
        """
        urls = await self.fetch_urls(limit)
        paths = set()
        
        for url in urls:
            try:
                parsed = urlparse(url)
                path = parsed.path or "/"
                if path and not path.startswith('/'):
                    path = '/' + path
                paths.add(path)
            except Exception:
                continue
        
        return paths
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


async def fetch_wayback_urls(domain: str, limit: int = 1000) -> Set[str]:
    """Convenience function to fetch Wayback URLs."""
    wb = WaybackMachine(domain)
    try:
        return await wb.fetch_urls(limit)
    finally:
        await wb.close()