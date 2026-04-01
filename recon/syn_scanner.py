# recon/syn_scanner.py
import asyncio
import socket
import struct
import random
import time
from typing import List, Optional, Tuple
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SynScanResult:
    port: int
    state: str
    service: Optional[str] = None


class SynScanner:
    """
    SYN scan for fast port scanning.
    Requires root privileges for raw sockets.
    """
    
    def __init__(self, target: str, timeout: float = 1.0, concurrency: int = 1000):
        self.target = target
        self.timeout = timeout
        self.concurrency = concurrency
        self._running = False
        self._results: List[SynScanResult] = []
        
        self.src_ip = self._get_source_ip()
        self.src_port = random.randint(1024, 65535)
    
    def _get_source_ip(self) -> str:
        """Get local IP address."""
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((self.target, 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "0.0.0.0"
        finally:
            s.close()
        return ip
    
    def _checksum(self, data: bytes) -> int:
        """Calculate IP checksum."""
        s = 0
        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i + 1] if i + 1 < len(data) else 0)
            s += w
        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s
    
    def craft_syn_packet(self, dst_ip: str, dst_port: int) -> bytes:
        """Create SYN packet."""
        # IP header
        ip_ihl = 5
        ip_ver = 4
        ip_tos = 0
        ip_tot_len = 20 + 20
        ip_id = random.randint(0, 65535)
        ip_frag_off = 0
        ip_ttl = 64
        ip_proto = socket.IPPROTO_TCP
        ip_check = 0
        ip_saddr = socket.inet_aton(self.src_ip)
        ip_daddr = socket.inet_aton(dst_ip)
        
        ip_header = struct.pack('!BBHHHBBH4s4s',
            (ip_ver << 4) + ip_ihl, ip_tos, ip_tot_len,
            ip_id, ip_frag_off, ip_ttl, ip_proto,
            ip_check, ip_saddr, ip_daddr
        )
        
        # TCP header
        tcp_src = self.src_port
        tcp_dst = dst_port
        tcp_seq = random.randint(0, 0xFFFFFFFF)
        tcp_ack_seq = 0
        tcp_doff = 5
        tcp_flags = 0x02  # SYN flag
        tcp_window = socket.htons(1024)
        tcp_check = 0
        tcp_urg_ptr = 0
        
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
            (tcp_doff << 4), tcp_flags, tcp_window,
            tcp_check, tcp_urg_ptr
        )
        
        # Pseudo header for checksum
        pseudo_header = struct.pack('!4s4sBBH',
            ip_saddr, ip_daddr, 0, socket.IPPROTO_TCP, len(tcp_header)
        )
        psh = pseudo_header + tcp_header
        tcp_check = self._checksum(psh)
        
        # Rebuild TCP header with checksum
        tcp_header = struct.pack('!HHLLBBHHH',
            tcp_src, tcp_dst, tcp_seq, tcp_ack_seq,
            (tcp_doff << 4), tcp_flags, tcp_window,
            tcp_check, tcp_urg_ptr
        )
        
        return ip_header + tcp_header
    
    async def _send_syn(self, port: int) -> Tuple[int, bool]:
        """Send SYN packet and wait for response."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.settimeout(self.timeout)
            
            packet = self.craft_syn_packet(self.target, port)
            sock.sendto(packet, (self.target, 0))
            
            start = time.time()
            while time.time() - start < self.timeout:
                try:
                    data, addr = sock.recvfrom(1024)
                    # Parse TCP flags from response
                    if len(data) >= 40:
                        tcp_flags = data[33]
                        if tcp_flags & 0x12:  # SYN-ACK
                            return port, True
                        elif tcp_flags & 0x04:  # RST
                            return port, False
                except socket.timeout:
                    break
                except Exception:
                    pass
            
            sock.close()
            return port, False
            
        except PermissionError:
            logger.error("SYN scan requires root privileges")
            return port, False
        except Exception as e:
            logger.debug(f"SYN scan error on port {port}: {e}")
            return port, False
    
    async def scan(self, ports: List[int]) -> List[SynScanResult]:
        """Scan list of ports using SYN method."""
        self._results = []
        semaphore = asyncio.Semaphore(self.concurrency)
        
        async def scan_port(port: int):
            async with semaphore:
                port_num, is_open = await self._send_syn(port)
                if is_open:
                    self._results.append(SynScanResult(port=port_num, state="open"))
        
        tasks = [scan_port(p) for p in ports]
        await asyncio.gather(*tasks)
        
        return self._results


def syn_scan(target: str, ports: List[int], concurrency: int = 1000) -> List[SynScanResult]:
    """Wrapper for SYN scan."""
    scanner = SynScanner(target, concurrency=concurrency)
    return asyncio.run(scanner.scan(ports))