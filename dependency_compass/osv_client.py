from __future__ import annotations

from dataclasses import dataclass

import httpx

from dependency_compass.models import Ecosystem

OSV_BASE_URL = "https://api.osv.dev"
MAX_BATCH = 1000   # OSV per-request query limit
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
                 base_url: str = OSV_BASE_URL) -> None:
        self._http = httpx.Client(base_url=base_url, timeout=TIMEOUT,
                                  transport=transport)

    def _query_chunk(self, queries: list[PackageQuery]) -> list[list[str]]:
        """Return one list of vulnerability IDs per query, in input order."""
        body = {"queries": [
            {"package": {"name": q.name, "ecosystem": q.ecosystem.value},
             "version": q.version}
            for q in queries
        ]}
        try:
            response = self._http.post("/v1/querybatch", json=body)
            response.raise_for_status()
            results = response.json()["results"]
            ids = [[v["id"] for v in r.get("vulns", [])] for r in results]
        except (httpx.HTTPError, ValueError, KeyError,
                TypeError, AttributeError) as exc:
            raise OSVError(f"OSV request failed: {type(exc).__name__}") from exc
        if len(ids) != len(queries):
            raise OSVError("OSV returned a mismatched result count")
        return ids

    def query_batch(self, queries: list[PackageQuery]) -> list[list[str]]:
        """Return one list of vuln IDs per query, in input order.

        Splits into OSV-sized batches; any batch failure raises OSVError.
        """
        ids: list[list[str]] = []
        for start in range(0, len(queries), MAX_BATCH):
            ids.extend(self._query_chunk(queries[start:start + MAX_BATCH]))
        return ids
