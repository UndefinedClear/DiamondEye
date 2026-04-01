# core/wordlist_manager.py
"""
Centralized wordlist loading and caching.
"""

import os
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Optional, Set
from functools import lru_cache

ROOT_DIR = Path(__file__).parent.parent

logger = logging.getLogger(__name__)


class WordlistManager:
    """
    Centralized manager for loading and caching wordlists.
    
    Supports:
    - Async file loading
    - LRU caching
    - Automatic fallback to defaults
    - Dynamic reload
    """
    
    _instance = None
    _lock = asyncio.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.wordlists_dir = ROOT_DIR / "wordlists"
        self.res_dir = ROOT_DIR / "res" / "lists"
        
        self._cache: Dict[str, List[str]] = {}
        self._loading_tasks: Dict[str, asyncio.Task] = {}
        self._initialized = True
    
    def _get_file_path(self, name: str) -> Path:
        """Get file path for wordlist by name."""
        # First check wordlists dir
        path = self.wordlists_dir / name
        if path.exists():
            return path
        
        # Check subdirectories
        for subdir in self.wordlists_dir.iterdir():
            if subdir.is_dir():
                path = subdir / name
                if path.exists():
                    return path
        
        # Check res/lists
        path = self.res_dir / name
        if path.exists():
            return path
        
        # Check useragents subdir
        path = self.res_dir / "useragents" / name
        if path.exists():
            return path
        
        return None
    
    async def load_list(self, name: str, default: Optional[List[str]] = None) -> List[str]:
        """
        Load wordlist by name with caching.
        
        Args:
            name: Filename or identifier
            default: Default list if file not found
            
        Returns:
            List of strings
        """
        async with self._lock:
            if name in self._cache:
                return self._cache[name]
        
        # Load in background if not already loading
        if name not in self._loading_tasks:
            self._loading_tasks[name] = asyncio.create_task(
                self._load_file(name, default)
            )
        
        result = await self._loading_tasks[name]
        
        async with self._lock:
            self._cache[name] = result
            del self._loading_tasks[name]
        
        return result
    
    async def _load_file(self, name: str, default: Optional[List[str]] = None) -> List[str]:
        """Actually load file from disk."""
        file_path = self._get_file_path(name)
        
        if file_path and file_path.exists():
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = [line.strip() for line in f if line.strip()]
                    if lines:
                        logger.debug(f"Loaded {len(lines)} entries from {file_path}")
                        return lines
            except Exception as e:
                logger.warning(f"Failed to load {file_path}: {e}")
        
        # Fallback to default
        if default is not None:
            logger.warning(f"Using default list for {name}")
            return default
        
        logger.warning(f"No default list for {name}, returning empty")
        return []
    
    async def load_user_agents(self) -> List[str]:
        """Load user agents from file."""
        return await self.load_list(
            "useragents.txt",
            default=["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"]
        )
    
    async def load_paths(self) -> List[str]:
        """Load HTTP paths for fuzzing."""
        return await self.load_list(
            "combined.txt",
            default=["/", "/admin", "/api", "/login", "/wp-admin"]
        )
    
    async def load_subdomains(self) -> List[str]:
        """Load subdomain list."""
        return await self.load_list(
            "subdomains.txt",
            default=["www", "mail", "api", "admin", "test", "dev", "staging"]
        )
    
    async def load_referers(self) -> List[str]:
        """Load referer list."""
        return await self.load_list(
            "referers.txt",
            default=[
                "https://www.google.com/",
                "https://www.bing.com/",
                "https://www.yahoo.com/",
                "https://www.facebook.com/",
                "https://twitter.com/",
            ]
        )
    
    async def load_http_methods(self) -> List[str]:
        """Load HTTP methods."""
        return await self.load_list(
            "http_methods.txt",
            default=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
        )
    
    async def load_fuzz_methods(self) -> List[str]:
        """Load fuzz HTTP methods."""
        return await self.load_list(
            "http_methods_fuzz.txt",
            default=["PROPFIND", "REPORT", "MKCOL", "LOCK", "UNLOCK", "TRACE", "COPY", "MOVE"]
        )
    
    async def load_dns_servers(self) -> List[str]:
        """Load DNS servers."""
        return await self.load_list(
            "dns_servers.txt",
            default=["8.8.8.8", "8.8.4.4", "1.1.1.1", "9.9.9.9"]
        )
    
    async def load_bypass_headers(self) -> Dict[str, dict]:
        """Load bypass headers from JSON."""
        file_path = self.res_dir / "bypass_headers.json"
        if file_path.exists():
            try:
                import json
                with open(file_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load bypass headers: {e}")
        return {}
    
    def clear_cache(self):
        """Clear all cached lists."""
        self._cache.clear()
    
    async def preload(self, names: List[str]):
        """Preload multiple wordlists."""
        tasks = [self.load_list(name) for name in names]
        await asyncio.gather(*tasks)