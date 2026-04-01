# core/attack_config.py
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class AttackConfig:
    url: str
    
    workers: int = 10
    sockets_per_worker: int = 100
    pipeline_depth: int = 1
    duration: int = 0
    
    methods: List[str] = field(default_factory=lambda: ['GET'])
    method_fuzz: bool = False
    
    data_size: int = 0
    path_fuzz: bool = False
    
    useragents: List[str] = field(default_factory=list)
    referers: List[str] = field(default_factory=list)
    auth_token: Optional[str] = None
    junk_headers: bool = False
    header_flood: bool = False
    random_host: bool = False
    randomize_header_order: bool = True
    
    waf_type: Optional[str] = None
    bypass_headers: Optional[dict] = None
    auto_bypass: bool = False
    
    proxy: Optional[str] = None
    no_ssl_check: bool = False
    use_http2: bool = False
    use_http3: bool = False
    
    websocket: bool = False
    graphql_bomb: bool = False
    h2reset: bool = False
    slow_rate: float = 0.0
    extreme: bool = False
    flood: bool = False
    
    max_rps: int = 0
    max_bandwidth_mbps: float = 0
    jitter_percent: float = 10.0
    
    slow_connections: int = 1000
    connection_timeout: float = 5.0
    read_timeout: float = 10.0
    keepalive_timeout: float = 5.0
    
    debug: bool = False
    
    def __post_init__(self):
        if self.flood:
            self.slow_rate = 0.0
        if self.extreme:
            self.pipeline_depth = 1
            self.keepalive_timeout = 0.1