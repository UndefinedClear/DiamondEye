# core/data_pool.py
"""
Data pool for pre-generated request bodies.
"""

import random
import string
from typing import List


class DataPool:
    """
    Pool of pre-generated request bodies for POST/PUT requests.
    Reduces overhead of generating random data per request.
    """
    
    def __init__(self, data_size: int, pool_size: int = 100):
        """
        Initialize data pool.
        
        Args:
            data_size: Size of each data chunk in bytes
            pool_size: Number of pre-generated chunks
        """
        self.data_size = data_size
        self.pool_size = pool_size
        self._pool: List[str] = []
        self._generate()
    
    def _generate(self):
        """Generate pool of random data chunks."""
        for _ in range(self.pool_size):
            if random.random() < 0.5:
                # JSON-like payload
                payload_size = max(1, self.data_size - 15)
                data = f'{{"d": "{self._random_string(payload_size)}"}}'
                if len(data) < self.data_size:
                    data += 'X' * (self.data_size - len(data))
            else:
                # Binary-like random data
                data = 'X' * self.data_size
            self._pool.append(data)
    
    def _random_string(self, length: int) -> str:
        """Generate random string of given length."""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
    
    def get_random(self) -> str:
        """Get random data chunk from pool."""
        return random.choice(self._pool)
    
    def get_all(self) -> List[str]:
        """Get all data chunks."""
        return self._pool.copy()
    
    def refresh(self):
        """Refresh the pool with new random data."""
        self._pool.clear()
        self._generate()