"""Sliding-window rate limiter: per client plus one global cap.

In memory only, so limits reset on restart and aren't shared between
processes. Fine for a single free-tier instance. The global cap protects the
upstream services (OSV, KEV) even if an attacker rotates IPs.
"""
from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable

DEFAULT_WINDOW = 60.0
MAX_CLIENTS = 10_000   # bounds memory; oldest client is forgotten first


class RateLimiter:
    def __init__(self, per_client: int, global_limit: int,
                 window: float = DEFAULT_WINDOW, max_clients: int = MAX_CLIENTS,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._per_client = per_client
        self._global_limit = global_limit
        self._window = window
        self._max_clients = max_clients
        self._clock = clock
        self._lock = threading.Lock()
        self._global: deque[float] = deque()
        self._clients: OrderedDict[str, deque[float]] = OrderedDict()

    def _prune(self, hits: deque[float], now: float) -> None:
        while hits and hits[0] <= now - self._window:
            hits.popleft()

    def check(self, client: str) -> float | None:
        """Record a request. Returns None if allowed, else seconds to wait."""
        with self._lock:
            now = self._clock()
            hits = self._clients.pop(client, None) or deque()
            self._prune(hits, now)
            self._prune(self._global, now)
            if len(hits) >= self._per_client:
                wait = hits[0] + self._window - now
            elif len(self._global) >= self._global_limit:
                wait = self._global[0] + self._window - now
            else:
                wait = None
                hits.append(now)
                self._global.append(now)
            if hits:
                self._clients[client] = hits   # re-insert as most recent
            while len(self._clients) > self._max_clients:
                self._clients.popitem(last=False)
            return wait
