from __future__ import annotations

from dataclasses import dataclass

import httpx

from dependency_compass.models import Ecosystem

OSV_BASE_URL = "https://api.osv.dev"
MAX_BATCH = 1000   # OSV's per-request query limit (batch splitting comes later)
TIMEOUT = httpx.Timeout(10.0, connect=5.0)   # explicit: never wait forever


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

    def query_batch(self, queries: list[PackageQuery]) -> list[list[str]]:
        """Return one list of vulnerability IDs per query, in input order."""
        body = {"queries": [
            {"package": {"name": q.name, "ecosystem": q.ecosystem.value},
             "version": q.version}
            for q in queries
        ]}
        response = self._http.post("/v1/querybatch", json=body)
        response.raise_for_status()
        results = response.json()["results"]
        return [[v["id"] for v in r.get("vulns", [])] for r in results]
