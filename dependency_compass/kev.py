"""CISA Known Exploited Vulnerabilities (KEV) catalog: fetch, validate, cache.

Decisions:
- Cached in memory for KEV_TTL (CISA updates about once per working day).
- If a refresh fails, a copy younger than MAX_STALE is still used and the
  result says STALE. Older or no copy -> UNAVAILABLE, never "not in KEV".
- After a failed fetch we wait FAILURE_BACKOFF before trying again, so an
  outage doesn't add retry delays to every scan.
- Any malformed entry rejects the whole catalog: skipping one could hide
  an exploited CVE.
"""
from __future__ import annotations

import json
import re
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import Enum

import httpx

from dependency_compass.advisory import Advisory

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
KEV_TTL = 24 * 3600.0
MAX_STALE = 7 * 24 * 3600.0
FAILURE_BACKOFF = 300.0
MAX_BYTES = 10 * 1024 * 1024   # real catalog is ~1.5 MB
MAX_ENTRIES = 50_000
MAX_NAME = 200
MAX_ATTEMPTS = 3
BACKOFF_BASE = 0.5
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
TIMEOUT = httpx.Timeout(15.0, connect=5.0)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


class KEVError(Exception):
    """KEV catalog was unreachable or returned data we cannot trust."""


class KEVStatus(str, Enum):
    OK = "ok"
    STALE = "stale"               # refresh failed; using an older copy
    UNAVAILABLE = "unavailable"   # no usable copy; KEV status unknown


@dataclass(frozen=True)
class KEVEntry:
    cve_id: str
    name: str                     # truncated vulnerabilityName
    date_added: str
    due_date: str
    known_ransomware: bool


@dataclass(frozen=True)
class KEVCatalog:
    entries: Mapping[str, KEVEntry]
    released: str

    def match(self, advisory: Advisory) -> KEVEntry | None:
        """Return the KEV entry for any CVE in the advisory's id or aliases."""
        for ident in sorted({advisory.id, *advisory.aliases}):
            entry = self.entries.get(ident.upper())
            if entry is not None:
                return entry
        return None


@dataclass(frozen=True)
class KEVSnapshot:
    catalog: KEVCatalog | None
    status: KEVStatus


def _date(value: object) -> str:
    if not isinstance(value, str) or not DATE_RE.fullmatch(value):
        raise KEVError("malformed KEV date")
    return value


def _entry(item: object) -> KEVEntry:
    if not isinstance(item, dict):
        raise KEVError("malformed KEV entry")
    cve = item.get("cveID")
    if not isinstance(cve, str) or not CVE_RE.fullmatch(cve):
        raise KEVError("malformed KEV cveID")
    name = item.get("vulnerabilityName")
    return KEVEntry(cve, name[:MAX_NAME] if isinstance(name, str) else "",
                    _date(item.get("dateAdded")), _date(item.get("dueDate")),
                    item.get("knownRansomwareCampaignUse") == "Known")


def parse_kev_catalog(data: object) -> KEVCatalog:
    """Validate the KEV JSON. An empty catalog is an error, not 'all clear'."""
    if not isinstance(data, dict):
        raise KEVError("KEV catalog is not an object")
    vulns = data.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        raise KEVError("KEV catalog has no vulnerabilities list")
    if len(vulns) > MAX_ENTRIES:
        raise KEVError("KEV catalog has too many entries")
    entries = {e.cve_id: e for e in map(_entry, vulns)}
    released = data.get("dateReleased")
    return KEVCatalog(entries,
                      released[:40] if isinstance(released, str) else "unknown")


class KEVClient:
    def __init__(self, transport: httpx.BaseTransport | None = None,
                 url: str = KEV_URL,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._url = url
        self._sleep = sleep
        self._http = httpx.Client(timeout=TIMEOUT, transport=transport)

    def _download(self) -> bytes | None:
        """One attempt. Returns None on a transient failure worth retrying."""
        try:
            with self._http.stream("GET", self._url) as response:
                if response.status_code in RETRY_STATUSES:
                    return None
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_bytes():
                    body += chunk
                    if len(body) > MAX_BYTES:
                        raise KEVError("KEV catalog exceeds size limit")
                return bytes(body)
        except httpx.TransportError:
            return None
        except httpx.HTTPError as exc:
            raise KEVError(f"KEV request failed: {type(exc).__name__}") from exc

    def fetch(self) -> KEVCatalog:
        """Download and validate the catalog. Raises KEVError on any problem."""
        for attempt in range(MAX_ATTEMPTS):
            body = self._download()
            if body is not None:
                try:
                    return parse_kev_catalog(json.loads(body))
                except ValueError as exc:   # bad JSON or bad UTF-8
                    raise KEVError("KEV catalog is not valid JSON") from exc
            if attempt < MAX_ATTEMPTS - 1:
                self._sleep(BACKOFF_BASE * 2 ** attempt)
        raise KEVError("KEV unreachable after retries")


class KEVLookup:
    """Cached KEV catalog with stale fallback. Thread-safe for the web app."""

    def __init__(self, client: KEVClient, ttl: float = KEV_TTL,
                 max_stale: float = MAX_STALE,
                 failure_backoff: float = FAILURE_BACKOFF,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._client = client
        self._ttl = ttl
        self._max_stale = max_stale
        self._failure_backoff = failure_backoff
        self._clock = clock
        self._lock = threading.Lock()
        self._catalog: KEVCatalog | None = None
        self._fetched_at = 0.0
        self._failed_at: float | None = None

    def _fallback(self, now: float) -> KEVSnapshot:
        if (self._catalog is not None
                and now - self._fetched_at < self._max_stale):
            return KEVSnapshot(self._catalog, KEVStatus.STALE)
        return KEVSnapshot(None, KEVStatus.UNAVAILABLE)

    def get(self) -> KEVSnapshot:
        with self._lock:
            now = self._clock()
            if (self._catalog is not None
                    and now - self._fetched_at < self._ttl):
                return KEVSnapshot(self._catalog, KEVStatus.OK)
            if (self._failed_at is not None
                    and now - self._failed_at < self._failure_backoff):
                return self._fallback(now)
            try:
                catalog = self._client.fetch()
            except KEVError:
                self._failed_at = now
                return self._fallback(now)
            self._catalog, self._fetched_at, self._failed_at = catalog, now, None
            return KEVSnapshot(catalog, KEVStatus.OK)
