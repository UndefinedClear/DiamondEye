# plugins/secure_plugin_manager.py
import importlib.util
import hashlib
import json
import os
import inspect
import logging
from typing import Dict, List, Optional, Set
from pathlib import Path
import aiofiles
import asyncio
from colorama import Fore, Style

from plugins.plugin_manager import BasePlugin, PluginInfo

logger = logging.getLogger(__name__)


class PluginVerificationError(Exception):
    """Ошибка верификации плагина."""
    pass


class SecurePluginManager:
    """
    Безопасный менеджер плагинов с проверкой целостности.
    """
    
    def __init__(self, plugins_dir: str = "plugins", 
                 allowed_hashes_file: str = "plugins/allowed_hashes.json",
                 verify_signatures: bool = True):
        self.plugins_dir = Path(plugins_dir)
        self.allowed_hashes_file = Path(allowed_hashes_file)
        self.verify_signatures = verify_signatures
        
        self.plugins: Dict[str, BasePlugin] = {}
        self.allowed_hashes: Set[str] = set()
        self.plugin_hashes: Dict[str, str] = {}
        
        self._loaded = False
        self._lock = asyncio.Lock()
        
        self.plugins_dir.mkdir(exist_ok=True)
    
    async def load_allowed_hashes(self):
        """Загрузка списка разрешенных хешей."""
        if not self.allowed_hashes_file.exists():
            logger.warning(f"Allowed hashes file not found: {self.allowed_hashes_file}")
            return
        
        try:
            async with aiofiles.open(self.allowed_hashes_file, 'r') as f:
                content = await f.read()
                data = json.loads(content)
                self.allowed_hashes = set(data.get('allowed_hashes', []))
                self.plugin_hashes = data.get('plugins', {})
                logger.info(f"Loaded {len(self.allowed_hashes)} allowed hashes")
        except Exception as e:
            logger.error(f"Failed to load allowed hashes: {e}")
    
    async def save_allowed_hashes(self):
        """Сохранение списка разрешенных хешей."""
        data = {
            'allowed_hashes': list(self.allowed_hashes),
            'plugins': self.plugin_hashes
        }
        try:
            async with aiofiles.open(self.allowed_hashes_file, 'w') as f:
                await f.write(json.dumps(data, indent=2))
        except Exception as e:
            logger.error(f"Failed to save allowed hashes: {e}")
    
    async def calculate_plugin_hash(self, plugin_path: Path) -> str:
        """Вычисление SHA-256 хеша плагина."""
        sha256 = hashlib.sha256()
        async with aiofiles.open(plugin_path, 'rb') as f:
            while chunk := await f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    async def verify_plugin(self, plugin_path: Path) -> bool:
        """Проверка целостности плагина."""
        if not self.verify_signatures:
            return True
        
        plugin_hash = await self.calculate_plugin_hash(plugin_path)
        plugin_name = plugin_path.stem
        
        if plugin_hash in self.allowed_hashes:
            return True
        
        print(f"\n{Fore.YELLOW}⚠️  Unknown plugin: {plugin_name}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Hash: {plugin_hash}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Do you want to allow this plugin? (y/N): {Style.RESET_ALL}", end="")
        
        response = input().strip().lower()
        if response == 'y':
            self.allowed_hashes.add(plugin_hash)
            self.plugin_hashes[plugin_name] = plugin_hash
            await self.save_allowed_hashes()
            return True
        
        return False
    
    async def scan_plugin_for_malware(self, plugin_path: Path, plugin_hash: str) -> List[str]:
        """
        Базовое сканирование плагина на подозрительный код.
        """
        warnings = []
        
        try:
            content = plugin_path.read_text(encoding='utf-8')
            
            dangerous_imports = [
                'subprocess', 'os.system', 'os.popen', 'shutil.rmtree',
                'eval(', 'exec(', '__import__', 'compile(', 'open(',
                'socket.socket', 'urllib.request', 'requests.get',
                'base64.b64decode', 'pickle.loads'
            ]
            
            for dangerous in dangerous_imports:
                if dangerous in content:
                    warnings.append(f"Contains {dangerous}")
            
            if 'import subprocess' in content or 'os.system' in content:
                warnings.append("May execute system commands")
            
            lines = content.split('\n')
            if any(len(line) > 500 for line in lines):
                warnings.append("Contains very long lines (possible obfuscation)")
            
            if content.count('base64.b64decode') > 2:
                warnings.append("Multiple base64 decodes (possible payload)")
            
        except Exception as e:
            warnings.append(f"Scan error: {e}")
        
        return warnings
    
    async def get_plugin_files(self) -> List[Path]:
        """Get all .py files in plugins directory (excluding system files)."""
        plugin_files = list(self.plugins_dir.glob("*.py"))
        plugin_files.extend(self.plugins_dir.glob("*/*.py"))
        
        exclude = ['__init__.py', 'plugin_manager.py', 'secure_plugin_manager.py', 'example_plugin.py']
        plugin_files = [f for f in plugin_files if f.name not in exclude]
        
        return plugin_files
    
    async def add_plugin(self, plugin_path: str, force: bool = False) -> bool:
        """
        Add a new plugin from file.
        
        Args:
            plugin_path: Path to plugin file (absolute or relative to plugins_dir)
            force: If True, skip warnings and auto-approve
        
        Returns:
            True if added successfully
        """
        path = Path(plugin_path)
        if not path.is_absolute():
            path = self.plugins_dir / path
            if not path.exists() and not path.suffix:
                path = path.with_suffix('.py')
        
        if not path.exists():
            logger.error(f"Plugin not found: {path}")
            return False
        
        if path.suffix != '.py':
            logger.error(f"Plugin must be a .py file: {path}")
            return False
        
        plugin_hash = await self.calculate_plugin_hash(path)
        
        if plugin_hash in self.allowed_hashes:
            logger.info(f"Plugin already allowed: {path.name}")
            return True
        
        warnings = await self.scan_plugin_for_malware(path, plugin_hash)
        
        print(f"\n{Fore.CYAN}📦 Plugin: {path.name}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📁 Path: {path}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔑 Hash: {plugin_hash}{Style.RESET_ALL}")
        
        if warnings:
            print(f"\n{Fore.YELLOW}⚠️  Security warnings:{Style.RESET_ALL}")
            for w in warnings:
                print(f"  - {w}")
            print()
        
        if not force:
            print(f"{Fore.YELLOW}Do you want to allow this plugin? (y/N): {Style.RESET_ALL}", end="")
            response = input().strip().lower()
            if response != 'y':
                print(f"{Fore.RED}Cancelled.{Style.RESET_ALL}")
                return False
        else:
            print(f"{Fore.YELLOW}Force mode: auto-approving plugin{Style.RESET_ALL}")
        
        self.allowed_hashes.add(plugin_hash)
        self.plugin_hashes[path.stem] = plugin_hash
        await self.save_allowed_hashes()
        
        print(f"{Fore.GREEN}✅ Plugin added successfully!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}💡 Run --list-plugins to see it{Style.RESET_ALL}")
        
        return True
    
    async def discover_plugins(self):
        """Load only approved plugins."""
        async with self._lock:
            if self._loaded:
                return
            
            await self.load_allowed_hashes()
            
            plugin_files = await self.get_plugin_files()
            
            for plugin_file in plugin_files:
                plugin_hash = await self.calculate_plugin_hash(plugin_file)
                
                if plugin_hash not in self.allowed_hashes:
                    logger.debug(f"Skipping unapproved plugin: {plugin_file.name}")
                    continue
                
                try:
                    module_name = f"plugins.{plugin_file.stem}"
                    spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                    
                    if not spec or not spec.loader:
                        logger.error(f"Failed to create spec for {plugin_file}")
                        continue
                    
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    for name, obj in inspect.getmembers(module):
                        if (inspect.isclass(obj) and 
                            issubclass(obj, BasePlugin) and 
                            obj != BasePlugin):
                            
                            try:
                                plugin_instance = obj()
                                plugin_info = plugin_instance.get_info()
                                
                                self.plugins[plugin_info.name] = plugin_instance
                                logger.info(f"✅ Loaded plugin: {plugin_info.name} v{plugin_info.version}")
                                
                            except Exception as e:
                                logger.error(f"Failed to instantiate plugin {name}: {e}")
                    
                except Exception as e:
                    logger.error(f"Failed to load plugin {plugin_file.name}: {e}")
            
            self._loaded = True
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Получение плагина по имени."""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[PluginInfo]:
        """Список плагинов."""
        return [p.get_info() for p in self.plugins.values()]
    
    async def execute_plugin(self, plugin_name: str, target: str, **kwargs):
        """Безопасное выполнение плагина с таймаутом."""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin {plugin_name} not found")
        
        try:
            result = await asyncio.wait_for(
                plugin.execute(target, **kwargs),
                timeout=kwargs.get('timeout', 300)
            )
            return result
        except asyncio.TimeoutError:
            logger.error(f"Plugin {plugin_name} execution timed out")
            raise
        except Exception as e:
            logger.error(f"Plugin {plugin_name} execution failed: {e}")
            raise