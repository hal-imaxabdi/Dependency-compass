from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass

import httpx

from dependency_compass.models import Ecosystem

OSV_BASE_URL = "https://api.osv.dev"
MAX_BATCH = 1000   # OSV per-request query limit
MAX_PAGES = 20   # cap on pagination rounds per batch
MAX_ATTEMPTS = 4   # total tries per request (1 + 3 retries)
BACKOFF_BASE = 0.5   # seconds; doubles each retry
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
TIMEOUT = httpx.Timeout(10.0, connect=5.0)   # explicit: never wait forever


class OSVError(Exception):
    """OSV was unreachable or returned data we cannot trust."""


@dataclass(frozen=True)
class PackageQuery:
    name: str
    ecosystem: Ecosystem
    version: str


class OSVClient:
    def __init__(self, transport: httpx.BaseTransport | None = None,
                 base_url: str = OSV_BASE_URL,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self._sleep = sleep
        self._http = httpx.Client(base_url=base_url, timeout=TIMEOUT,
                                  transport=transport)

    def _send(self, queries: list[dict]) -> httpx.Response:
        """POST with retries on transient failures only."""
        for attempt in range(MAX_ATTEMPTS):
            try:
                response = self._http.post("/v1/querybatch",
                                           json={"queries": queries})
            except httpx.TransportError as exc:
                if attempt == MAX_ATTEMPTS - 1:
                    raise OSVError("OSV unreachable after retries") from exc
            else:
                if response.status_code not in RETRY_STATUSES:
                    return response
                if attempt == MAX_ATTEMPTS - 1:
                    raise OSVError("OSV unavailable after retries")
            self._sleep(BACKOFF_BASE * 2 ** attempt)
        raise OSVError("OSV request failed")

    def _post(self, queries: list[dict]) -> list[tuple[list[str], object]]:
        """One request. Returns (vuln ids, next_page_token) per query."""
        try:
            response = self._send(queries)
            response.raise_for_status()
            results = response.json()["results"]
            parsed = [([v["id"] for v in r.get("vulns", [])],
                       r.get("next_page_token")) for r in results]
        except (httpx.HTTPError, ValueError, KeyError,
                TypeError, AttributeError) as exc:
            raise OSVError(f"OSV request failed: {type(exc).__name__}") from exc
        if len(parsed) != len(queries):
            raise OSVError("OSV returned a mismatched result count")
        if any(t is not None and not isinstance(t, str) for _, t in parsed):
            raise OSVError("OSV returned a malformed page token")
        return parsed

    def _query_chunk(self, queries: list[PackageQuery]) -> list[list[str]]:
        payload = [
            {"package": {"name": q.name, "ecosystem": q.ecosystem.value},
             "version": q.version}
            for q in queries
        ]
        ids: list[list[str]] = [[] for _ in queries]
        tokens: dict[int, str] = {}
        pending = list(range(len(queries)))
        for _ in range(MAX_PAGES):
            batch = [{**payload[i], **({"page_token": tokens[i]}
                                       if i in tokens else {})}
                     for i in pending]
            next_pending = []
            for i, (page_ids, token) in zip(pending, self._post(batch)):
                ids[i].extend(page_ids)
                if token:
                    tokens[i] = token
                    next_pending.append(i)
            if not next_pending:
                return ids
            pending = next_pending
        raise OSVError("OSV pagination exceeded the page limit")

    def query_batch(self, queries: list[PackageQuery]) -> list[list[str]]:
        """Return one list of vuln IDs per query, in input order.

        Splits into OSV-sized batches; any batch failure raises OSVError.
        """
        ids: list[list[str]] = []
        for start in range(0, len(queries), MAX_BATCH):
            ids.extend(self._query_chunk(queries[start:start + MAX_BATCH]))
        return ids
