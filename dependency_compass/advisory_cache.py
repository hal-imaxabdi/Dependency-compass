from __future__ import annotations

import time
from collections import OrderedDict
from collections.abc import Callable

from dependency_compass.advisory import Advisory, _norm, parse_advisory
from dependency_compass.models import Ecosystem
from dependency_compass.osv_client import OSVClient

DEFAULT_TTL = 3600.0
MAX_ENTRIES = 2000


class AdvisoryCache:
    """In-memory TTL cache of parsed advisories. Never stores uploads."""

    def __init__(self, client: OSVClient, ttl: float = DEFAULT_TTL,
                 max_entries: int = MAX_ENTRIES,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._client = client
        self._ttl = ttl
        self._max = max_entries
        self._clock = clock
        self._items: OrderedDict[tuple, tuple[float, Advisory]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._items)

    def get(self, vuln_id: str, name: str, ecosystem: Ecosystem) -> Advisory:
        key = (vuln_id, ecosystem, _norm(name, ecosystem))
        hit = self._items.get(key)
        if hit is not None and self._clock() - hit[0] < self._ttl:
            return hit[1]
        self._items.pop(key, None)
        record = self._client.get_vulnerability(vuln_id)
        advisory = parse_advisory(record, name, ecosystem)
        self._items[key] = (self._clock(), advisory)
        while len(self._items) > self._max:
            self._items.popitem(last=False)
        return advisory
