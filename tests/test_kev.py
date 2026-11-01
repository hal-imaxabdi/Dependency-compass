import json

import httpx
import pytest

from dependency_compass import kev as kev_mod
from dependency_compass.advisory import Advisory
from dependency_compass.kev import (
    KEVClient, KEVError, KEVLookup, KEVStatus, parse_kev_catalog,
)


def item(cve="CVE-2024-0001", **over):
    base = {"cveID": cve, "vulnerabilityName": "Example RCE",
            "dateAdded": "2024-05-01", "dueDate": "2024-05-22",
            "knownRansomwareCampaignUse": "Known"}
    base.update(over)
    return base


def catalog(*items):
    return {"dateReleased": "2026-11-01T12:00:00Z",
            "vulnerabilities": list(items) or [item()]}


def adv(vid, *aliases):
    return Advisory(vid, aliases, "", "high", (), "2026-01-01T00:00:00Z", False)


class FakeKEVServer:
    """Serves a queue of responses (or exceptions) in order."""

    def __init__(self, *responses):
        self.responses, self.calls = list(responses), 0

    def __call__(self, request):
        self.calls += 1
        r = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(r, Exception):
            raise r
        return r


def client(server):
    return KEVClient(transport=httpx.MockTransport(server), sleep=lambda s: None)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


# --- parsing ---------------------------------------------------------------

def test_parse_valid_catalog():
    cat = parse_kev_catalog(catalog(item(), item("CVE-2023-12345",
                                                 knownRansomwareCampaignUse="Unknown")))
    assert set(cat.entries) == {"CVE-2024-0001", "CVE-2023-12345"}
    assert cat.entries["CVE-2024-0001"].known_ransomware is True
    assert cat.entries["CVE-2023-12345"].known_ransomware is False
    assert cat.released == "2026-11-01T12:00:00Z"


@pytest.mark.parametrize("data", [
    [],                                          # not an object
    {"vulnerabilities": []},                     # empty is not "all clear"
    {"vulnerabilities": "x"},
    catalog(item(cve="CVE-24-1")),               # bad CVE id
    catalog(item(cve=123)),
    catalog(item(dateAdded="yesterday")),
    catalog(item(), "not a dict"),               # one bad entry rejects all
])
def test_parse_rejects_malformed(data):
    with pytest.raises(KEVError):
        parse_kev_catalog(data)


def test_parse_rejects_too_many_entries(monkeypatch):
    monkeypatch.setattr(kev_mod, "MAX_ENTRIES", 1)
    with pytest.raises(KEVError):
        parse_kev_catalog(catalog(item(), item("CVE-2024-0002")))


def test_untrusted_text_is_truncated():
    cat = parse_kev_catalog({"dateReleased": "x" * 500, "vulnerabilities": [
        item(vulnerabilityName="n" * 500)]})
    assert len(cat.released) == 40
    assert len(cat.entries["CVE-2024-0001"].name) == kev_mod.MAX_NAME


# --- matching --------------------------------------------------------------

def test_match_by_alias_and_by_id():
    cat = parse_kev_catalog(catalog())
    assert cat.match(adv("GHSA-aaaa", "CVE-2024-0001")).cve_id == "CVE-2024-0001"
    assert cat.match(adv("CVE-2024-0001")) is not None
    assert cat.match(adv("cve-2024-0001")) is not None
    assert cat.match(adv("GHSA-bbbb", "PYSEC-1")) is None


# --- client ----------------------------------------------------------------

def test_fetch_ok():
    server = FakeKEVServer(httpx.Response(200, json=catalog()))
    assert "CVE-2024-0001" in client(server).fetch().entries


def test_fetch_retries_transient_then_succeeds():
    server = FakeKEVServer(httpx.Response(503),
                           httpx.ConnectError("down"),
                           httpx.Response(200, json=catalog()))
    assert client(server).fetch().entries
    assert server.calls == 3


def test_fetch_gives_up_after_max_attempts():
    server = FakeKEVServer(httpx.Response(503))
    with pytest.raises(KEVError):
        client(server).fetch()
    assert server.calls == kev_mod.MAX_ATTEMPTS


def test_fetch_does_not_retry_client_errors():
    server = FakeKEVServer(httpx.Response(404))
    with pytest.raises(KEVError):
        client(server).fetch()
    assert server.calls == 1


@pytest.mark.parametrize("body", [b"not json", b"\xff\xfe", b"[]"])
def test_fetch_rejects_bad_body(body):
    with pytest.raises(KEVError):
        client(FakeKEVServer(httpx.Response(200, content=body))).fetch()


def test_fetch_rejects_oversized_body(monkeypatch):
    monkeypatch.setattr(kev_mod, "MAX_BYTES", 100)
    body = json.dumps(catalog(*[item(f"CVE-2024-{i:04d}") for i in range(10)]))
    with pytest.raises(KEVError, match="size"):
        client(FakeKEVServer(httpx.Response(200, content=body))).fetch()


# --- lookup cache ----------------------------------------------------------

class FakeClient:
    def __init__(self, *results):
        self.results, self.calls = list(results), 0

    def fetch(self):
        self.calls += 1
        r = self.results.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def test_lookup_caches_within_ttl():
    clock, fake = Clock(), FakeClient(parse_kev_catalog(catalog()))
    lookup = KEVLookup(fake, ttl=100, clock=clock)
    assert lookup.get().status is KEVStatus.OK
    clock.now += 99
    assert lookup.get().status is KEVStatus.OK
    assert fake.calls == 1


def test_lookup_refreshes_after_ttl():
    clock = Clock()
    fake = FakeClient(parse_kev_catalog(catalog()),
                      parse_kev_catalog(catalog(item("CVE-2025-9999"))))
    lookup = KEVLookup(fake, ttl=100, clock=clock)
    lookup.get()
    clock.now += 100
    assert "CVE-2025-9999" in lookup.get().catalog.entries


def test_lookup_unavailable_without_any_copy():
    lookup = KEVLookup(FakeClient(KEVError("down")), clock=Clock())
    snap = lookup.get()
    assert snap.status is KEVStatus.UNAVAILABLE and snap.catalog is None


def test_lookup_serves_stale_copy_then_gives_up():
    clock = Clock()
    cat = parse_kev_catalog(catalog())
    fake = FakeClient(cat, KEVError("down"), KEVError("down"))
    lookup = KEVLookup(fake, ttl=100, max_stale=1000, failure_backoff=0,
                       clock=clock)
    lookup.get()
    clock.now += 500
    snap = lookup.get()
    assert snap.status is KEVStatus.STALE and snap.catalog is cat
    clock.now += 500                      # copy now too old to trust
    assert lookup.get().status is KEVStatus.UNAVAILABLE


def test_lookup_backs_off_after_failure():
    clock = Clock()
    fake = FakeClient(KEVError("down"), parse_kev_catalog(catalog()))
    lookup = KEVLookup(fake, failure_backoff=300, clock=clock)
    lookup.get()
    clock.now += 299
    assert lookup.get().status is KEVStatus.UNAVAILABLE
    assert fake.calls == 1                # no refetch during backoff
    clock.now += 1
    assert lookup.get().status is KEVStatus.OK
    assert fake.calls == 2
