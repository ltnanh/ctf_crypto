from collections import deque
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from typing import Optional
import hashlib


@dataclass
class CachedRequest:
    timestamp: datetime
    method: str
    params_hash: str
    response: str
    ip_address: str

class RequestCache:
    def __init__(self, max_size: int = 20):
        """Initialize request cache with configurable max size (10-20 recommended)"""
        if not 10 <= max_size <= 20:
            raise ValueError("Cache size must be between 10 and 20 elements")

        self.max_size = max_size
        self.cache = deque(maxlen=max_size)

    def add(
        self,
        method: str,
        params: dict,
        response: str,
        ip_address: str,
        
    ) -> None:
        """Add a request to the cache"""
        params_str = str(sorted(params.items()))
        params_hash = hashlib.sha256(params_str.encode()).hexdigest()[:16]

        cached_request = CachedRequest(
            timestamp=datetime.now(timezone.utc),
            method=method,
            params_hash=params_hash,
            response=response,
            ip_address=ip_address

        )
        self.cache.append(cached_request)
        if len(self.cache) > self.max_size:
            self.cache.popleft()


    def check_request(self, method: str, params: dict, ip_address: str) -> Optional[str]:
        params_str = str(sorted(params.items()))
        params_hash = hashlib.sha256(params_str.encode()).hexdigest()[:16]

        for req in self.cache:
            if (
                req.method == method
                and req.params_hash == params_hash
                and req.ip_address == ip_address
            ):
                # Check if cache entry is still valid (1 minute TTL)
                if datetime.now(timezone.utc) - req.timestamp < timedelta(seconds=10):
                    return req.response
        return None
    def __len__(self) -> int:
        return len(self.cache)

    def __repr__(self) -> str:
        return f"RequestCache(size={len(self.cache)}/{self.max_size})"
