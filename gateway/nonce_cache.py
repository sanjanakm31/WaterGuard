"""
gateway/nonce_cache.py

A thread-safe, TTL-based cache of (client_id, nonce) pairs the Gateway has
already accepted for HMAC verification. Used to detect replay attacks:
if the exact same nonce is presented twice by the same client_id within the
TTL window, the second presentation is rejected regardless of whether its
HMAC and timestamp are otherwise valid (which they will be, in a genuine
replay, since the attacker is resending bytes that were valid the first time).

`seen_before()` performs the check-and-record as a single atomic operation
under one lock acquisition specifically to avoid a check-then-insert race
between two connection-handling threads racing on the same nonce.
"""

from __future__ import annotations

import threading
import time


class NonceCache:
    def __init__(self, ttl_seconds: float):
        self._ttl_seconds = ttl_seconds
        self._lock = threading.Lock()
        # key -> UNIX time at which this entry may be purged
        self._store: dict[tuple[str, str], float] = {}

    def _purge_expired_locked(self, now: float) -> None:
        expired_keys = [key for key, expiry in self._store.items() if expiry <= now]
        for key in expired_keys:
            del self._store[key]

    def seen_before(self, client_id: str, nonce: str) -> bool:
        """
        Returns True if (client_id, nonce) was already recorded and has not
        yet expired (i.e. this presentation is a replay and must be
        rejected). Returns False and records the pair (so a *subsequent*
        presentation of the same pair will return True) otherwise.
        """
        now = time.time()
        key = (client_id, nonce)
        with self._lock:
            self._purge_expired_locked(now)
            if key in self._store:
                return True
            self._store[key] = now + self._ttl_seconds
            return False

    def size(self) -> int:
        with self._lock:
            return len(self._store)
