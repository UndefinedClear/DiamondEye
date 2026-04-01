# recon/crt.py
import asyncio
import aiohttp
from typing import List, Set, Optional
import logging
import json
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CertificateTransparency:
    """
    Fetch subdomains from Certificate Transparency logs.
    Uses crt.sh API.
    """
    
    API_URL = "https://crt.sh/?q={}&output=json"
    
    def __init__(self, domain: str):
        self.domain = domain
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def fetch_subdomains(self) -> Set[str]:
        """
        Fetch subdomains from crt.sh.
        
        Returns:
            Set of unique subdomains
        """
        subdomains = set()
        
        # Search for certificates containing domain
        query = f"%.{self.domain}"
        
        try:
            session = await self._get_session()
            async with session.get(self.API_URL.format(query)) as resp:
                if resp.status == 200:
                    try:
                        data = await resp.json()
                        for entry in data:
                            name_value = entry.get('name_value', '')
                            if name_value:
                                # Split multiple domains (separated by \n)
                                for name in name_value.split('\n'):
                                    name = name.strip().lower()
                                    if name.endswith(self.domain) and name != self.domain:
                                        subdomains.add(name)
                                    elif name == self.domain:
                                        subdomains.add(name)
                    except json.JSONDecodeError:
                        logger.warning("Failed to parse crt.sh response")
                else:
                    logger.warning(f"crt.sh returned {resp.status}")
                    
        except Exception as e:
            logger.error(f"Failed to fetch from crt.sh: {e}")
        
        logger.info(f"Fetched {len(subdomains)} subdomains from certificate logs")
        return subdomains
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()


async def fetch_crt_subdomains(domain: str) -> Set[str]:
    """Convenience function to fetch subdomains from crt.sh."""
    crt = CertificateTransparency(domain)
    try:
        return await crt.fetch_subdomains()
    finally:
        await crt.close()