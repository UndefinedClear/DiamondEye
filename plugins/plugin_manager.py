# plugins/plugin_manager.py
import importlib
import pkgutil
import inspect
from typing import Dict, List, Type, Any
from abc import ABC, abstractmethod
from dataclasses import dataclass
import asyncio


@dataclass
class PluginInfo:
    name: str
    version: str
    author: str
    description: str
    attack_types: List[str]  # ['http', 'tcp', 'dns', etc]
    

class BasePlugin(ABC):
    """Базовый класс для всех плагинов DiamondEye"""
    
    @abstractmethod
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Инициализация плагина"""
        pass
    
    @abstractmethod
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Выполнение основной логики плагина"""
        pass
    
    @abstractmethod
    async def cleanup(self):
        """Очистка ресурсов"""
        pass
    
    def get_info(self) -> PluginInfo:
        """Получение информации о плагине"""
        return PluginInfo(
            name=self.__class__.__name__,
            version="1.0",
            author="Unknown",
            description="No description",
            attack_types=[]
        )


class PluginManager:
    """Менеджер плагинов для динамической загрузки расширений"""
    
    def __init__(self, plugins_dir: str = "plugins"):
        self.plugins_dir = plugins_dir
        self.plugins: Dict[str, BasePlugin] = {}
        self._loaded = False
        
    async def discover_plugins(self):
        """Автоматическое обнаружение плагинов"""
        import os
        import sys
        
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir, exist_ok=True)
            # Создаем пример плагина
            self._create_example_plugin()
        
        # Добавляем директорию плагинов в путь Python
        if self.plugins_dir not in sys.path:
            sys.path.insert(0, self.plugins_dir)
        
        # Ищем файлы плагинов
        plugin_files = []
        for root, dirs, files in os.walk(self.plugins_dir):
            for file in files:
                if file.endswith('.py') and not file.startswith('_'):
                    plugin_files.append(os.path.join(root, file))
        
        # Загружаем плагины
        for plugin_file in plugin_files:
            try:
                plugin_name = os.path.basename(plugin_file)[:-3]
                module_name = f"plugins.{plugin_name}"
                
                # Динамическая загрузка модуля
                spec = importlib.util.spec_from_file_location(module_name, plugin_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Ищем классы, наследующие BasePlugin
                for name, obj in inspect.getmembers(module):
                    if (inspect.isclass(obj) and 
                        issubclass(obj, BasePlugin) and 
                        obj != BasePlugin):
                        
                        plugin_instance = obj()
                        plugin_info = plugin_instance.get_info()
                        
                        self.plugins[plugin_info.name] = plugin_instance
                        print(f"✅ Loaded plugin: {plugin_info.name} v{plugin_info.version}")
                        
            except Exception as e:
                print(f"❌ Failed to load plugin {plugin_file}: {e}")
        
        self._loaded = True
    
    def _create_example_plugin(self):
        """Создание примера плагина"""
        example_plugin = '''# plugins/example_plugin.py
from plugins.plugin_manager import BasePlugin, PluginInfo
from typing import Dict, Any
import asyncio
import random


class ExamplePlugin(BasePlugin):
    """Пример плагина для тестирования"""
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        self.config = config
        self.counter = 0
        return True
    
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Пример выполнения плагина"""
        self.counter += 1
        
        # Имитация работы плагина
        await asyncio.sleep(0.1)
        
        return {
            'target': target,
            'execution_id': self.counter,
            'status': 'success',
            'data': f'Processed {target} (#{self.counter})',
            'random_value': random.randint(1, 100)
        }
    
    async def cleanup(self):
        self.counter = 0
    
    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="ExamplePlugin",
            version="1.0.0",
            author="DiamondEye Team",
            description="Пример плагина для демонстрации системы расширений",
            attack_types=['http', 'tcp']
        )
'''
        
        with open(f"{self.plugins_dir}/example_plugin.py", "w", encoding="utf-8") as f:
            f.write(example_plugin)
    
    def get_plugin(self, name: str) -> BasePlugin:
        """Получение плагина по имени"""
        return self.plugins.get(name)
    
    def list_plugins(self) -> List[PluginInfo]:
        """Список всех загруженных плагинов"""
        return [plugin.get_info() for plugin in self.plugins.values()]
    
    async def execute_plugin(self, plugin_name: str, target: str, **kwargs) -> Dict[str, Any]:
        """Выполнение плагина"""
        plugin = self.get_plugin(plugin_name)
        if not plugin:
            raise ValueError(f"Plugin {plugin_name} not found")
        
        return await plugin.execute(target, **kwargs)