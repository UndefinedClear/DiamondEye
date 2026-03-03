# core/rate_limiter.py
import asyncio
import time
from typing import Optional


class RateLimiter:
    """
    Ограничитель скорости запросов (RPS) и пропускной способности (bandwidth).
    Активируется ТОЛЬКО если max_rps > 0 или max_bandwidth_mbps > 0.
    По умолчанию (0) - никаких ограничений.
    """
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0):
        """
        Args:
            max_rps: Максимальное количество запросов в секунду (0 = без лимита)
            max_bandwidth_mbps: Максимальная пропускная способность в Mbps (0 = без лимита)
        """
        self.max_rps = max_rps
        self.max_bandwidth_mbps = max_bandwidth_mbps
        self.max_bytes_per_sec = int(max_bandwidth_mbps * 1024 * 1024 / 8) if max_bandwidth_mbps > 0 else 0
        
        # Для RPS лимита
        self._rps_tokens = 0
        self._rps_last_refill = time.time()
        self._rps_lock = asyncio.Lock()
        
        # Для bandwidth лимита
        self._bytes_this_sec = 0
        self._bw_last_reset = time.time()
        self._bw_lock = asyncio.Lock()
        
        # Статистика
        self.total_limited = 0
        self.total_allowed = 0
        
    async def acquire(self, bytes_count: int = 0) -> bool:
        """
        Получить разрешение на отправку запроса.
        
        Args:
            bytes_count: Размер запроса в байтах (для bandwidth лимита)
            
        Returns:
            True если можно отправлять, False если нужно пропустить/отбросить
        """
        # Если нет лимитов - сразу разрешаем
        if self.max_rps == 0 and self.max_bytes_per_sec == 0:
            self.total_allowed += 1
            return True
        
        # Проверка RPS лимита
        if self.max_rps > 0:
            if not await self._acquire_rps():
                self.total_limited += 1
                return False
        
        # Проверка bandwidth лимита
        if self.max_bytes_per_sec > 0 and bytes_count > 0:
            if not await self._acquire_bandwidth(bytes_count):
                self.total_limited += 1
                return False
        
        self.total_allowed += 1
        return True
    
    async def _acquire_rps(self) -> bool:
        """Внутренняя проверка RPS с использованием token bucket."""
        async with self._rps_lock:
            now = time.time()
            elapsed = now - self._rps_last_refill
            
            # Добавляем новые токены (max_rps в секунду)
            self._rps_tokens += elapsed * self.max_rps
            if self._rps_tokens > self.max_rps:
                self._rps_tokens = self.max_rps
            
            self._rps_last_refill = now
            
            if self._rps_tokens >= 1:
                self._rps_tokens -= 1
                return True
            
            # Нет токенов - нужно ждать
            wait_time = (1 - self._rps_tokens) / self.max_rps
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                self._rps_tokens = 0  # После ожидания даём один токен
                return True
            
            return False
    
    async def _acquire_bandwidth(self, bytes_count: int) -> bool:
        """Внутренняя проверка bandwidth с использованием sliding window."""
        async with self._bw_lock:
            now = time.time()
            
            # Сброс счётчика каждую секунду
            if now - self._bw_last_reset >= 1.0:
                self._bytes_this_sec = 0
                self._bw_last_reset = now
            
            # Проверяем, не превысим ли лимит
            if self._bytes_this_sec + bytes_count <= self.max_bytes_per_sec:
                self._bytes_this_sec += bytes_count
                return True
            
            # Превышение лимита - ждём до конца текущей секунды
            wait_time = 1.0 - (now - self._bw_last_reset)
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                # После ожидания сбрасываем и даём зелёный свет
                self._bytes_this_sec = bytes_count
                self._bw_last_reset = time.time()
                return True
            
            return False
    
    async def wait_if_needed(self, bytes_count: int = 0) -> bool:
        """
        Ожидать, пока лимиты позволят отправить запрос.
        Возвращает True, если можно отправлять после ожидания.
        """
        return await self.acquire(bytes_count)
    
    def get_stats(self) -> dict:
        """Получить статистику работы лимитера."""
        return {
            'max_rps': self.max_rps,
            'max_bandwidth_mbps': self.max_bandwidth_mbps,
            'allowed': self.total_allowed,
            'limited': self.total_limited,
            'limited_percent': (self.total_limited / (self.total_allowed + self.total_limited) * 100) 
                              if (self.total_allowed + self.total_limited) > 0 else 0
        }


class BurstRateLimiter(RateLimiter):
    """
    Расширенный ограничитель с поддержкой burst-режима.
    Позволяет кратковременные всплески, но усредняет до max_rps.
    """
    
    def __init__(self, max_rps: int = 0, max_bandwidth_mbps: float = 0, burst_factor: float = 2.0):
        super().__init__(max_rps, max_bandwidth_mbps)
        self.burst_factor = burst_factor
        self._burst_tokens = max_rps * burst_factor if max_rps > 0 else 0
        
    async def _acquire_rps(self) -> bool:
        """Token bucket с поддержкой burst."""
        async with self._rps_lock:
            now = time.time()
            elapsed = now - self._rps_last_refill
            
            # Восстанавливаем токены
            new_tokens = elapsed * self.max_rps
            self._rps_tokens = min(self._rps_tokens + new_tokens, self.max_rps * self.burst_factor)
            self._burst_tokens = min(self._burst_tokens + new_tokens, self.max_rps * self.burst_factor)
            
            self._rps_last_refill = now
            
            # Сначала используем burst токены
            if self._burst_tokens >= 1:
                self._burst_tokens -= 1
                return True
            elif self._rps_tokens >= 1:
                self._rps_tokens -= 1
                return True
            
            # Нет токенов - ждём
            wait_time = (1 - self._rps_tokens) / self.max_rps
            if wait_time > 0:
                await asyncio.sleep(wait_time)
                self._rps_tokens = max(0, self._rps_tokens - 1)
                return True
            
            return False