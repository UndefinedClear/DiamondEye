# core/rate_limiter.py
"""
Rate limiting with token bucket, sharding, and jitter support.
"""

import asyncio
import time
import random
from typing import List, Optional, Dict
from collections import deque
import logging

logger = logging.getLogger(__name__)


class TokenBucket:
    """Token bucket algorithm without blocking."""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """Try to consume tokens."""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False


class RateLimiter:
    """Base rate limiter with token bucket."""
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0):
        self.max_rps = max_rps
        self.max_bandwidth_mbps = max_bandwidth_mbps
        self.max_bytes_per_sec = int(max_bandwidth_mbps * 1024 * 1024 / 8) if max_bandwidth_mbps > 0 else 0
        
        self.rps_bucket: Optional[TokenBucket] = None
        self.bw_bucket: Optional[TokenBucket] = None
        
        if max_rps > 0:
            self.rps_bucket = TokenBucket(max_rps, int(max_rps * 2))
        
        if self.max_bytes_per_sec > 0:
            self.bw_bucket = TokenBucket(self.max_bytes_per_sec, int(self.max_bytes_per_sec * 2))
        
        self.total_allowed = 0
        self.total_limited = 0
        self._stats_lock = asyncio.Lock()
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        """Try to acquire permission for a request."""
        if self.rps_bucket:
            if not await self.rps_bucket.consume():
                async with self._stats_lock:
                    self.total_limited += 1
                return False
        
        if self.bw_bucket and bytes_count > 0:
            if not await self.bw_bucket.consume(bytes_count):
                async with self._stats_lock:
                    self.total_limited += 1
                return False
        
        async with self._stats_lock:
            self.total_allowed += 1
        return True
    
    async def wait_if_needed(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        """Wait until allowed to send request."""
        max_attempts = 100
        for attempt in range(max_attempts):
            if await self.acquire(bytes_count, key):
                return True
            await asyncio.sleep(0.001 * (2 ** attempt))
        return False
    
    def get_stats(self) -> dict:
        """Get statistics."""
        total = self.total_allowed + self.total_limited
        return {
            'max_rps': self.max_rps,
            'max_bandwidth_mbps': self.max_bandwidth_mbps,
            'allowed': self.total_allowed,
            'limited': self.total_limited,
            'limited_percent': (self.total_limited / total * 100) if total > 0 else 0,
        }


class ShardedRateLimiter(RateLimiter):
    """Rate limiter with sharding for fairness."""
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0, shards: int = 16):
        super().__init__(max_rps, max_bandwidth_mbps)
        self.shards = shards
        
        self.rps_shards: List[Optional[TokenBucket]] = []
        self.bw_shards: List[Optional[TokenBucket]] = []
        
        if max_rps > 0:
            per_shard = max_rps / shards
            for _ in range(shards):
                self.rps_shards.append(TokenBucket(per_shard, int(per_shard * 2)))
        
        if self.max_bytes_per_sec > 0:
            per_shard = self.max_bytes_per_sec / shards
            for _ in range(shards):
                self.bw_shards.append(TokenBucket(per_shard, int(per_shard * 2)))
    
    def _get_shard(self, key: Optional[str] = None) -> int:
        """Determine shard for request."""
        if key is None:
            return random.randint(0, self.shards - 1)
        return hash(key) % self.shards
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        """Try to acquire with sharding."""
        shard = self._get_shard(key)
        
        if self.rps_shards:
            if not await self.rps_shards[shard].consume():
                async with self._stats_lock:
                    self.total_limited += 1
                return False
        
        if self.bw_shards and bytes_count > 0:
            if not await self.bw_shards[shard].consume(bytes_count):
                async with self._stats_lock:
                    self.total_limited += 1
                return False
        
        async with self._stats_lock:
            self.total_allowed += 1
        return True
    
    def get_stats(self) -> dict:
        stats = super().get_stats()
        stats.update({'shards': self.shards})
        return stats


class BurstRateLimiter(ShardedRateLimiter):
    """Rate limiter with burst support."""
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0,
                 shards: int = 16, burst_factor: float = 3.0,
                 burst_duration: float = 5.0):
        super().__init__(max_rps, max_bandwidth_mbps, shards)
        self.burst_factor = burst_factor
        self.burst_duration = burst_duration
        
        self.burst_active = False
        self.burst_start = 0
        self.burst_tokens_consumed = 0
        self.burst_tokens_limit = int(max_rps * burst_factor * burst_duration) if max_rps > 0 else 0
        
        self._burst_lock = asyncio.Lock()
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        shard = self._get_shard(key)
        
        async with self._burst_lock:
            now = time.time()
            
            if self.burst_active and now - self.burst_start > self.burst_duration:
                self.burst_active = False
                self.burst_tokens_consumed = 0
                logger.debug("Burst mode expired")
            
            if self.rps_shards:
                if self.burst_active and self.burst_tokens_consumed < self.burst_tokens_limit:
                    if not await self.rps_shards[shard].consume():
                        self.burst_tokens_consumed += 1
                else:
                    if not await self.rps_shards[shard].consume():
                        if not self.burst_active and self.burst_tokens_limit > 0:
                            self.burst_active = True
                            self.burst_start = now
                            self.burst_tokens_consumed = 1
                            logger.debug("Burst mode activated")
                        else:
                            async with self._stats_lock:
                                self.total_limited += 1
                            return False
            
            if self.bw_shards and bytes_count > 0:
                if not await self.bw_shards[shard].consume(bytes_count):
                    async with self._stats_lock:
                        self.total_limited += 1
                    return False
        
        async with self._stats_lock:
            self.total_allowed += 1
        return True
    
    def get_stats(self) -> dict:
        stats = super().get_stats()
        stats.update({
            'burst_active': self.burst_active,
            'burst_factor': self.burst_factor,
            'burst_duration': self.burst_duration,
            'burst_tokens_used': self.burst_tokens_consumed,
            'burst_tokens_limit': self.burst_tokens_limit
        })
        return stats


class JitteredRateLimiter(BurstRateLimiter):
    """
    Rate limiter with random jitter to avoid detection patterns.
    Adds randomized delay variation to make traffic appear human-like.
    """
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0,
                 shards: int = 16, burst_factor: float = 3.0,
                 burst_duration: float = 5.0, jitter_percent: float = 10.0):
        """
        Args:
            jitter_percent: Random delay variation as percentage of base interval (0-100)
        """
        super().__init__(max_rps, max_bandwidth_mbps, shards, burst_factor, burst_duration)
        self.jitter_percent = min(100.0, max(0.0, jitter_percent))
        self._last_acquire_time: Dict[int, float] = {}
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        shard = self._get_shard(key)
        
        # Apply jitter delay before checking limits
        if self.jitter_percent > 0 and self.max_rps > 0:
            base_interval = 1.0 / self.max_rps
            jitter_range = base_interval * (self.jitter_percent / 100.0)
            jitter_delay = random.uniform(-jitter_range, jitter_range)
            
            if jitter_delay > 0:
                await asyncio.sleep(jitter_delay)
        
        return await super().acquire(bytes_count, key)
    
    def get_stats(self) -> dict:
        stats = super().get_stats()
        stats.update({'jitter_percent': self.jitter_percent})
        return stats


class AdaptiveRateLimiter(JitteredRateLimiter):
    """Rate limiter with dynamic adaptation based on latency."""
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0,
                 shards: int = 16, target_latency_ms: float = 100.0,
                 burst_factor: float = 3.0, burst_duration: float = 5.0,
                 jitter_percent: float = 10.0):
        super().__init__(max_rps, max_bandwidth_mbps, shards, burst_factor, burst_duration, jitter_percent)
        self.target_latency_ms = target_latency_ms
        self.latency_history = deque(maxlen=100)
        self.current_factor = 1.0
        self._adjust_task: Optional[asyncio.Task] = None
        self._running = False
    
    async def start_adaptive_adjustment(self):
        """Start background adaptation loop."""
        self._running = True
        self._adjust_task = asyncio.create_task(self._adjust_loop())
    
    async def stop_adaptive_adjustment(self):
        """Stop adaptation loop."""
        self._running = False
        if self._adjust_task:
            self._adjust_task.cancel()
            try:
                await self._adjust_task
            except asyncio.CancelledError:
                pass
    
    def record_latency(self, latency_ms: float):
        """Record latency for adaptation."""
        self.latency_history.append(latency_ms)
    
    async def _adjust_loop(self):
        """Adaptation loop."""
        while self._running:
            await asyncio.sleep(1.0)
            
            if len(self.latency_history) < 10:
                continue
            
            avg_latency = sum(self.latency_history) / len(self.latency_history)
            
            if avg_latency > self.target_latency_ms * 1.5:
                self.current_factor = max(0.5, self.current_factor * 0.9)
                logger.info(f"Rate limiter: reducing to {self.current_factor:.2f} (latency: {avg_latency:.1f}ms)")
            elif avg_latency < self.target_latency_ms * 0.7:
                self.current_factor = min(2.0, self.current_factor * 1.1)
                logger.info(f"Rate limiter: increasing to {self.current_factor:.2f} (latency: {avg_latency:.1f}ms)")
            
            if self.max_rps > 0:
                per_shard = (self.max_rps * self.current_factor) / self.shards
                for bucket in self.rps_shards:
                    bucket.rate = per_shard
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        old_rps_shards = self.rps_shards
        old_bw_shards = self.bw_shards
        
        try:
            if self.current_factor != 1.0 and self.rps_shards:
                self.rps_shards = []
                for bucket in old_rps_shards:
                    new_bucket = TokenBucket(bucket.rate * self.current_factor, bucket.capacity)
                    self.rps_shards.append(new_bucket)
            
            return await super().acquire(bytes_count, key)
        finally:
            if old_rps_shards:
                self.rps_shards = old_rps_shards