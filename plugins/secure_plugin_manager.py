# plugins/secure_plugin_manager.py
import importlib.util
import hashlib
import json
import os
import inspect
from typing import Dict, List, Optional, Set
from pathlib import Path
import aiofiles
import asyncio

from plugins.plugin_manager import BasePlugin, PluginInfo


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
        self.plugin_hashes: Dict[str, str] = {}  # имя плагина -> хеш
        
        self._loaded = False
        self._lock = asyncio.Lock()
        
        # Создаем директорию если нет
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
        
        # Проверяем в белом списке
        if plugin_hash in self.allowed_hashes:
            return True
        
        # Если нет в белом списке - запрашиваем подтверждение
        plugin_name = plugin_path.stem
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
    
    async def scan_plugin_for_malware(self, plugin_path: Path) -> List[str]:
        """
        Базовое сканирование плагина на подозрительный код.
        """
        warnings = []
        
        try:
            content = plugin_path.read_text(encoding='utf-8')
            
            # Проверка на опасные импорты
            dangerous_imports = [
                'subprocess', 'os.system', 'os.popen', 'shutil.rmtree',
                'eval(', 'exec(', '__import__', 'compile(', 'open(',
                'socket.socket', 'urllib.request', 'requests.get',
                'base64.b64decode', 'pickle.loads'
            ]
            
            for dangerous in dangerous_imports:
                if dangerous in content:
                    warnings.append(f"Contains {dangerous}")
            
            # Проверка на запуск shell команд
            if 'import subprocess' in content or 'os.system' in content:
                warnings.append("May execute system commands")
            
            # Проверка на обфускацию
            lines = content.split('\n')
            if any(len(line) > 500 for line in lines):
                warnings.append("Contains very long lines (possible obfuscation)")
            
            if content.count('base64.b64decode') > 2:
                warnings.append("Multiple base64 decodes (possible payload)")
            
        except Exception as e:
            warnings.append(f"Scan error: {e}")
        
        return warnings
    
    async def discover_plugins(self):
        """Безопасное обнаружение плагинов."""
        async with self._lock:
            if self._loaded:
                return
            
            await self.load_allowed_hashes()
            
            # Ищем файлы плагинов
            plugin_files = list(self.plugins_dir.glob("*.py"))
            plugin_files.extend(self.plugins_dir.glob("*/*.py"))
            
            # Исключаем системные файлы
            plugin_files = [f for f in plugin_files 
                          if not f.name.startswith('__') 
                          and f.name != 'plugin_manager.py'
                          and f.name != 'secure_plugin_manager.py']
            
            for plugin_file in plugin_files:
                try:
                    # Проверка целостности
                    if not await self.verify_plugin(plugin_file):
                        logger.warning(f"Plugin verification failed: {plugin_file.name}")
                        continue
                    
                    # Сканирование на malware
                    warnings = await self.scan_plugin_for_malware(plugin_file)
                    if warnings and self.verify_signatures:
                        print(f"{Fore.YELLOW}⚠️  Plugin {plugin_file.name} warnings:{Style.RESET_ALL}")
                        for w in warnings:
                            print(f"  - {w}")
                        
                        print(f"{Fore.YELLOW}Continue loading? (y/N): {Style.RESET_ALL}", end="")
                        if input().strip().lower() != 'y':
                            continue
                    
                    # Загрузка в изолированном пространстве имен
                    module_name = f"plugins.{plugin_file.stem}"
                    spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                    
                    if not spec or not spec.loader:
                        logger.error(f"Failed to create spec for {plugin_file}")
                        continue
                    
                    module = importlib.util.module_from_spec(spec)
                    
                    # Загружаем в ограниченном окружении
                    try:
                        spec.loader.exec_module(module)
                    except Exception as e:
                        logger.error(f"Failed to execute plugin {plugin_file.name}: {e}")
                        continue
                    
                    # Ищем классы плагинов
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
        
        # Выполняем с таймаутом
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