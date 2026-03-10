# core/rate_limiter.py
import asyncio
import time
import random
from typing import List, Optional, Dict
from collections import deque
import logging

logger = logging.getLogger(__name__)


class TokenBucket:
    """Алгоритм token bucket без блокировок."""
    
    def __init__(self, rate: float, capacity: int):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.last_refill = time.time()
        self._lock = asyncio.Lock()
    
    async def consume(self, tokens: int = 1) -> bool:
        """Попытка потребить токены."""
        async with self._lock:
            now = time.time()
            elapsed = now - self.last_refill
            
            # Добавляем новые токены
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False


class RateLimiter:
    """Базовый rate limiter с token bucket."""
    
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
        
        # Статистика
        self.total_allowed = 0
        self.total_limited = 0
        self._stats_lock = asyncio.Lock()
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        """Попытка получить разрешение на запрос."""
        # Проверка RPS
        if self.rps_bucket:
            if not await self.rps_bucket.consume():
                async with self._stats_lock:
                    self.total_limited += 1
                return False
        
        # Проверка bandwidth
        if self.bw_bucket and bytes_count > 0:
            if not await self.bw_bucket.consume(bytes_count):
                async with self._stats_lock:
                    self.total_limited += 1
                return False
        
        async with self._stats_lock:
            self.total_allowed += 1
        return True
    
    async def wait_if_needed(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        """Ожидать, пока лимиты позволят отправить запрос."""
        max_attempts = 100
        for attempt in range(max_attempts):
            if await self.acquire(bytes_count, key):
                return True
            
            # Экспоненциальный backoff
            await asyncio.sleep(0.001 * (2 ** attempt))
        
        return False
    
    def get_stats(self) -> dict:
        """Получить статистику."""
        total = self.total_allowed + self.total_limited
        return {
            'max_rps': self.max_rps,
            'max_bandwidth_mbps': self.max_bandwidth_mbps,
            'allowed': self.total_allowed,
            'limited': self.total_limited,
            'limited_percent': (self.total_limited / total * 100) if total > 0 else 0,
        }


class ShardedRateLimiter(RateLimiter):
    """
    Rate limiter с шардированием для fairness и производительности.
    Использует несколько независимых bucket'ов.
    """
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0, shards: int = 16):
        super().__init__(max_rps, max_bandwidth_mbps)
        self.shards = shards
        
        # Создаем шарды
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
        """Определение шарда для запроса."""
        if key is None:
            # Случайное распределение
            return random.randint(0, self.shards - 1)
        # Хэширование для fairness
        return hash(key) % self.shards
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        """Попытка получить разрешение с шардированием."""
        shard = self._get_shard(key)
        
        # Проверка RPS
        if self.rps_shards:
            if not await self.rps_shards[shard].consume():
                async with self._stats_lock:
                    self.total_limited += 1
                return False
        
        # Проверка bandwidth
        if self.bw_shards and bytes_count > 0:
            if not await self.bw_shards[shard].consume(bytes_count):
                async with self._stats_lock:
                    self.total_limited += 1
                return False
        
        async with self._stats_lock:
            self.total_allowed += 1
        return True
    
    def get_stats(self) -> dict:
        """Расширенная статистика."""
        stats = super().get_stats()
        stats.update({
            'shards': self.shards
        })
        return stats


class BurstRateLimiter(ShardedRateLimiter):
    """
    Rate limiter с поддержкой burst-режима.
    Позволяет кратковременные всплески трафика выше среднего.
    """
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0,
                 shards: int = 16, burst_factor: float = 3.0,
                 burst_duration: float = 5.0):
        """
        Args:
            burst_factor: Во сколько раз можно превысить лимит в пике
            burst_duration: Длительность burst-режима в секундах
        """
        super().__init__(max_rps, max_bandwidth_mbps, shards)
        self.burst_factor = burst_factor
        self.burst_duration = burst_duration
        
        # Для отслеживания burst-режима
        self.burst_active = False
        self.burst_start = 0
        self.burst_tokens_consumed = 0
        self.burst_tokens_limit = int(max_rps * burst_factor * burst_duration) if max_rps > 0 else 0
        
        self._burst_lock = asyncio.Lock()
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        """
        Попытка получить разрешение с поддержкой burst.
        """
        shard = self._get_shard(key)
        
        # Проверка burst-режима
        async with self._burst_lock:
            now = time.time()
            
            # Проверяем не истек ли burst
            if self.burst_active and now - self.burst_start > self.burst_duration:
                self.burst_active = False
                self.burst_tokens_consumed = 0
                logger.debug("Burst mode expired")
            
            # Проверка RPS с burst
            if self.rps_shards:
                if self.burst_active and self.burst_tokens_consumed < self.burst_tokens_limit:
                    # В burst-режиме: ослабляем проверку
                    if not await self.rps_shards[shard].consume():
                        # Используем burst токены
                        self.burst_tokens_consumed += 1
                else:
                    # Обычный режим
                    if not await self.rps_shards[shard].consume():
                        # Пытаемся активировать burst
                        if not self.burst_active and self.burst_tokens_limit > 0:
                            self.burst_active = True
                            self.burst_start = now
                            self.burst_tokens_consumed = 1
                            logger.debug("Burst mode activated")
                        else:
                            async with self._stats_lock:
                                self.total_limited += 1
                            return False
            
            # Проверка bandwidth
            if self.bw_shards and bytes_count > 0:
                if not await self.bw_shards[shard].consume(bytes_count):
                    async with self._stats_lock:
                        self.total_limited += 1
                    return False
        
        async with self._stats_lock:
            self.total_allowed += 1
        return True
    
    def get_stats(self) -> dict:
        """Расширенная статистика."""
        stats = super().get_stats()
        stats.update({
            'burst_active': self.burst_active,
            'burst_factor': self.burst_factor,
            'burst_duration': self.burst_duration,
            'burst_tokens_used': self.burst_tokens_consumed,
            'burst_tokens_limit': self.burst_tokens_limit
        })
        return stats


class AdaptiveRateLimiter(BurstRateLimiter):
    """
    Rate limiter с динамической адаптацией на основе latency.
    """
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0,
                 shards: int = 16, target_latency_ms: float = 100.0,
                 burst_factor: float = 3.0, burst_duration: float = 5.0):
        super().__init__(max_rps, max_bandwidth_mbps, shards, burst_factor, burst_duration)
        self.target_latency_ms = target_latency_ms
        self.latency_history = deque(maxlen=100)
        self.current_factor = 1.0
        self._adjust_task: Optional[asyncio.Task] = None
    
    async def start_adaptive_adjustment(self):
        """Запуск фоновой адаптации."""
        self._adjust_task = asyncio.create_task(self._adjust_loop())
    
    async def stop_adaptive_adjustment(self):
        """Остановка адаптации."""
        if self._adjust_task:
            self._adjust_task.cancel()
            try:
                await self._adjust_task
            except asyncio.CancelledError:
                pass
    
    def record_latency(self, latency_ms: float):
        """Записать latency для адаптации."""
        self.latency_history.append(latency_ms)
    
    async def _adjust_loop(self):
        """Цикл адаптации."""
        while True:
            await asyncio.sleep(1.0)
            
            if len(self.latency_history) < 10:
                continue
            
            avg_latency = sum(self.latency_history) / len(self.latency_history)
            
            # Адаптация на основе latency
            if avg_latency > self.target_latency_ms * 1.5:
                # Слишком медленно - уменьшаем rate
                self.current_factor = max(0.5, self.current_factor * 0.9)
                logger.info(f"Rate limiter: reducing factor to {self.current_factor:.2f} (latency: {avg_latency:.1f}ms)")
            elif avg_latency < self.target_latency_ms * 0.7:
                # Быстро - можно увеличить
                self.current_factor = min(2.0, self.current_factor * 1.1)
                logger.info(f"Rate limiter: increasing factor to {self.current_factor:.2f} (latency: {avg_latency:.1f}ms)")
            
            # Обновляем rate в шардах
            if self.max_rps > 0:
                per_shard = (self.max_rps * self.current_factor) / self.shards
                for bucket in self.rps_shards:
                    bucket.rate = per_shard
    
    async def acquire(self, bytes_count: int = 0, key: Optional[str] = None) -> bool:
        """Адаптивный acquire с учётом current_factor."""
        # Временно модифицируем лимиты для этого запроса
        old_rps_shards = self.rps_shards
        old_bw_shards = self.bw_shards
        
        try:
            if self.current_factor != 1.0 and self.rps_shards:
                # Создаем временные шарды с изменённым rate
                self.rps_shards = []
                for bucket in old_rps_shards:
                    new_bucket = TokenBucket(bucket.rate * self.current_factor, bucket.capacity)
                    self.rps_shards.append(new_bucket)
            
            return await super().acquire(bytes_count, key)
        finally:
            # Восстанавливаем оригинальные шарды
            if old_rps_shards:
                self.rps_shards = old_rps_shards