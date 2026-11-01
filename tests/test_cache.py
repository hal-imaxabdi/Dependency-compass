import httpx
import pytest

from dependency_compass.advisory_cache import AdvisoryCache
from dependency_compass.models import Ecosystem
from dependency_compass.osv_client import OSVClient, OSVError

REC = {"id": "CVE-2020-1", "modified": "2026-01-01T00:00:00Z",
       "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                     "ranges": [{"type": "SEMVER", "events": [
                         {"introduced": "0"}, {"fixed": "1.0.0"}]}]}]}


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


def make(handler, clock, **kw):
    client = OSVClient(transport=httpx.MockTransport(handler),
                       sleep=lambda s: None)
    return AdvisoryCache(client, clock=clock, **kw)


def test_second_lookup_within_ttl_is_served_from_cache():
    calls, clock = [], Clock()

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json=REC)

    cache = make(handler, clock)
    first = cache.get("CVE-2020-1", "lodash", Ecosystem.NPM)
    second = cache.get("CVE-2020-1", "lodash", Ecosystem.NPM)
    assert first == second and len(calls) == 1


def test_expired_entry_is_refetched():
    calls, clock = [], Clock()

    def handler(request):
        calls.append(1)
        return httpx.Response(200, json=REC)

    cache = make(handler, clock, ttl=60)
    cache.get("CVE-2020-1", "lodash", Ecosystem.NPM)
    clock.now = 61
    cache.get("CVE-2020-1", "lodash", Ecosystem.NPM)
    assert len(calls) == 2


def test_expired_entry_is_not_served_when_osv_is_down():
    clock, state = Clock(), {"up": True}

    def handler(request):
        if state["up"]:
            return httpx.Response(200, json=REC)
        return httpx.Response(500)

    cache = make(handler, clock, ttl=60)
    cache.get("CVE-2020-1", "lodash", Ecosystem.NPM)
    clock.now, state["up"] = 61, False
    with pytest.raises(OSVError):
        cache.get("CVE-2020-1", "lodash", Ecosystem.NPM)


def test_errors_are_not_cached():
    calls, clock = [], Clock()

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            return httpx.Response(404)
        return httpx.Response(200, json=REC)

    cache = make(handler, clock)
    with pytest.raises(OSVError):
        cache.get("CVE-2020-1", "lodash", Ecosystem.NPM)
    assert cache.get("CVE-2020-1", "lodash", Ecosystem.NPM).id == "CVE-2020-1"


def test_cache_size_is_bounded():
    calls = []

    def handler(request):
        calls.append(1)
        vid = request.url.path.rsplit("/", 1)[1]
        return httpx.Response(200, json={**REC, "id": vid})

    cache = make(handler, Clock(), max_entries=2)
    for vid in ("CVE-2020-1", "CVE-2020-2", "CVE-2020-3"):
        cache.get(vid, "lodash", Ecosystem.NPM)
    assert len(cache) == 2
    cache.get("CVE-2020-1", "lodash", Ecosystem.NPM)  # oldest was evicted
    assert len(calls) == 4
