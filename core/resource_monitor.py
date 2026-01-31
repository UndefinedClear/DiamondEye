# core/resource_monitor.py
import psutil
import asyncio
import time
import statistics
from typing import Dict, List, Optional
from datetime import datetime
from colorama import Fore, Style


class ResourceMonitor:
    """Продвинутый мониторинг системных ресурсов"""
    
    def __init__(self, alert_threshold: int = 90):
        self.start_time = time.time()
        self.alert_threshold = alert_threshold
        
        # История метрик
        self.cpu_history: List[float] = []
        self.ram_history: List[float] = []
        self.network_history: List[Dict] = []
        self.connection_history: List[int] = []
        
        # Счетчики
        self.samples = 0
        self.alerts = 0
        
        # Базовые значения
        self.net_io_start = psutil.net_io_counters()
        self.disk_io_start = psutil.disk_io_counters()
        
        # Флаги
        self._monitoring = False
        
    async def monitor(self, interval: float = 1.0):
        """Запуск мониторинга ресурсов"""
        self._monitoring = True
        
        print(f"{Fore.CYAN}📊 Starting resource monitoring (interval: {interval}s){Style.RESET_ALL}")
        
        last_net = self.net_io_start
        last_disk = self.disk_io_start
        
        while self._monitoring:
            try:
                # Собираем метрики
                cpu_percent = psutil.cpu_percent(interval=None)
                ram_percent = psutil.virtual_memory().percent
                net_io = psutil.net_io_counters()
                disk_io = psutil.disk_io_counters() if psutil.disk_io_counters() else None
                
                # Вычисляем разницу по сети
                sent_bytes = net_io.bytes_sent - last_net.bytes_sent
                recv_bytes = net_io.bytes_recv - last_net.bytes_recv
                
                # Вычисляем разницу по диску (если доступно)
                disk_read = 0
                disk_write = 0
                if disk_io and last_disk:
                    disk_read = disk_io.read_bytes - last_disk.read_bytes
                    disk_write = disk_io.write_bytes - last_disk.write_bytes
                
                # Сохраняем историю
                self.cpu_history.append(cpu_percent)
                self.ram_history.append(ram_percent)
                self.network_history.append({
                    'timestamp': time.time(),
                    'sent_bytes': sent_bytes,
                    'recv_bytes': recv_bytes,
                    'sent_packets': net_io.packets_sent - last_net.packets_sent,
                    'recv_packets': net_io.packets_recv - last_net.packets_recv
                })
                
                # Подсчет активных соединений
                try:
                    connections = len(psutil.net_connections())
                    self.connection_history.append(connections)
                except:
                    connections = 0
                
                # Проверка на превышение порога
                alerts = []
                if cpu_percent > self.alert_threshold:
                    alerts.append(f"CPU: {cpu_percent:.1f}%")
                if ram_percent > self.alert_threshold:
                    alerts.append(f"RAM: {ram_percent:.1f}%")
                
                if alerts:
                    self.alerts += 1
                    alert_msg = ", ".join(alerts)
                    print(f"{Fore.RED}⚠️  High resource usage: {alert_msg}{Style.RESET_ALL}")
                
                # Вывод статистики
                self.samples += 1
                if self.samples % 10 == 0:  # Каждые 10 секунд
                    self.print_summary()
                
                # Обновляем последние значения
                last_net = net_io
                if disk_io:
                    last_disk = disk_io
                
                # Ждем интервал
                await asyncio.sleep(interval)
                
            except Exception as e:
                if 'debug' in globals() and globals()['debug']:
                    print(f"{Fore.YELLOW}⚠️  Monitor error: {e}{Style.RESET_ALL}")
                await asyncio.sleep(interval)
    
    def print_summary(self):
        """Вывод краткой статистики"""
        if not self.cpu_history:
            return
        
        duration = time.time() - self.start_time
        
        # Средние значения
        cpu_avg = statistics.mean(self.cpu_history[-10:]) if len(self.cpu_history) >= 10 else self.cpu_history[-1]
        ram_avg = statistics.mean(self.ram_history[-10:]) if len(self.ram_history) >= 10 else self.ram_history[-1]
        
        # Сетевая статистика
        if len(self.network_history) >= 2:
            recent = self.network_history[-1]
            sent_mbps = (recent['sent_bytes'] * 8) / 1024 / 1024  # в Mbps
            recv_mbps = (recent['recv_bytes'] * 8) / 1024 / 1024
            
            # Средняя скорость за последние 10 секунд
            if len(self.network_history) >= 10:
                avg_sent = sum(h['sent_bytes'] for h in self.network_history[-10:]) / 10
                avg_sent_mbps = (avg_sent * 8) / 1024 / 1024
            else:
                avg_sent_mbps = sent_mbps
        else:
            sent_mbps = recv_mbps = avg_sent_mbps = 0
        
        print(f"\n{Fore.CYAN}📈 Resource Summary:{Style.RESET_ALL}")
        print(f"   ⏱️  Duration: {int(duration)}s")
        print(f"   💻 CPU: {cpu_avg:.1f}% avg")
        print(f"   🧠 RAM: {ram_avg:.1f}% avg")
        print(f"   📡 Network: ↑{sent_mbps:.2f} Mbps, ↓{recv_mbps:.2f} Mbps")
        print(f"   📊 Avg Send Rate: {avg_sent_mbps:.2f} Mbps")
        
        if self.connection_history:
            avg_conn = statistics.mean(self.connection_history[-10:]) if len(self.connection_history) >= 10 else self.connection_history[-1]
            print(f"   🔗 Connections: {avg_conn:.0f} avg")
        
        if self.alerts > 0:
            print(f"   ⚠️  Alerts: {self.alerts}")
    
    def get_report(self) -> Dict:
        """Получение детального отчета"""
        if not self.cpu_history:
            return {}
        
        duration = time.time() - self.start_time
        
        # Основные метрики
        cpu_avg = statistics.mean(self.cpu_history) if self.cpu_history else 0
        cpu_max = max(self.cpu_history) if self.cpu_history else 0
        cpu_min = min(self.cpu_history) if self.cpu_history else 0
        
        ram_avg = statistics.mean(self.ram_history) if self.ram_history else 0
        ram_max = max(self.ram_history) if self.ram_history else 0
        ram_min = min(self.ram_history) if self.ram_history else 0
        
        # Сетевая статистика
        total_sent = sum(h['sent_bytes'] for h in self.network_history)
        total_recv = sum(h['recv_bytes'] for h in self.network_history)
        
        avg_sent_mbps = 0
        avg_recv_mbps = 0
        peak_sent_mbps = 0
        
        if self.network_history and duration > 0:
            avg_sent_mbps = (total_sent * 8) / duration / 1024 / 1024
            avg_recv_mbps = (total_recv * 8) / duration / 1024 / 1024
            
            # Пиковая скорость
            for h in self.network_history:
                sent_mbps = (h['sent_bytes'] * 8) / 1024 / 1024
                if sent_mbps > peak_sent_mbps:
                    peak_sent_mbps = sent_mbps
        
        # Статистика по соединениям
        conn_avg = statistics.mean(self.connection_history) if self.connection_history else 0
        conn_max = max(self.connection_history) if self.connection_history else 0
        
        return {
            'duration': duration,
            'samples': self.samples,
            'alerts': self.alerts,
            
            'cpu': {
                'average': cpu_avg,
                'maximum': cpu_max,
                'minimum': cpu_min,
                'samples': len(self.cpu_history)
            },
            
            'ram': {
                'average': ram_avg,
                'maximum': ram_max,
                'minimum': ram_min,
                'samples': len(self.ram_history)
            },
            
            'network': {
                'total_sent_bytes': total_sent,
                'total_recv_bytes': total_recv,
                'total_sent_mb': total_sent / 1024 / 1024,
                'total_recv_mb': total_recv / 1024 / 1024,
                'average_sent_mbps': avg_sent_mbps,
                'average_recv_mbps': avg_recv_mbps,
                'peak_sent_mbps': peak_sent_mbps,
                'samples': len(self.network_history)
            },
            
            'connections': {
                'average': conn_avg,
                'maximum': conn_max,
                'samples': len(self.connection_history)
            },
            
            'timestamp': datetime.now().isoformat()
        }
    
    def stop(self):
        """Остановка мониторинга"""
        self._monitoring = False
    
    def print_final_report(self):
        """Вывод финального отчета"""
        report = self.get_report()
        
        if not report:
            return
        
        print(f"\n{Fore.CYAN}📊 Final Resource Report:{Style.RESET_ALL}")
        print(f"{'='*50}")
        
        print(f"⏱️  Duration: {report['duration']:.1f}s")
        print(f"📊 Samples: {report['samples']}")
        print(f"⚠️  Alerts: {report['alerts']}")
        
        print(f"\n💻 CPU Usage:")
        print(f"   Average: {report['cpu']['average']:.1f}%")
        print(f"   Maximum: {report['cpu']['maximum']:.1f}%")
        print(f"   Minimum: {report['cpu']['minimum']:.1f}%")
        
        print(f"\n🧠 RAM Usage:")
        print(f"   Average: {report['ram']['average']:.1f}%")
        print(f"   Maximum: {report['ram']['maximum']:.1f}%")
        print(f"   Minimum: {report['ram']['minimum']:.1f}%")
        
        print(f"\n📡 Network Traffic:")
        print(f"   Total Sent: {report['network']['total_sent_mb']:.2f} MB")
        print(f"   Total Received: {report['network']['total_recv_mb']:.2f} MB")
        print(f"   Average Send Rate: {report['network']['average_sent_mbps']:.2f} Mbps")
        print(f"   Peak Send Rate: {report['network']['peak_sent_mbps']:.2f} Mbps")
        
        if report['connections']['samples'] > 0:
            print(f"\n🔗 Network Connections:")
            print(f"   Average: {report['connections']['average']:.1f}")
            print(f"   Maximum: {report['connections']['maximum']}")