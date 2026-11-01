import json

import httpx
import pytest

from dependency_compass import scanner
from dependency_compass.advisory_cache import AdvisoryCache
from dependency_compass.osv_client import OSVClient, OSVError
from dependency_compass.scanner import (
    UNPINNED_REASON, UnsupportedFileError, parse_file, scan,
)


def rec(vid, name, eco="PyPI", severity="HIGH", fixed="9.9.9", **over):
    base = {"id": vid, "modified": "2026-01-01T00:00:00Z",
            "database_specific": {"severity": severity},
            "affected": [{"package": {"name": name, "ecosystem": eco},
                          "ranges": [{"type": "ECOSYSTEM", "events": [
                              {"introduced": "0"}, {"fixed": fixed}]}]}]}
    base.update(over)
    return base


class FakeOSV:
    """Answers querybatch from `vulns` and GETs from `records`."""

    def __init__(self, vulns, records):
        self.vulns, self.records = vulns, records
        self.batches, self.gets = [], []

    def __call__(self, request):
        if request.method == "POST":
            qs = json.loads(request.content)["queries"]
            self.batches.append(qs)
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": v} for v in self.vulns.get(
                    (q["package"]["name"], q["version"]), [])]} for q in qs]})
        vid = request.url.path.rsplit("/", 1)[1]
        self.gets.append(vid)
        return httpx.Response(200, json=self.records[vid])


def run(filename, text, fake):
    client = OSVClient(transport=httpx.MockTransport(fake), sleep=lambda s: None)
    name, parsed = parse_file(filename, text)
    return scan(parsed, name, client, AdvisoryCache(client))


def test_vulnerable_and_clean_are_separated():
    fake = FakeOSV({("jinja2", "2.4.1"): ["PYSEC-1"]},
                   {"PYSEC-1": rec("PYSEC-1", "jinja2")})
    result = run("requirements.txt", "jinja2==2.4.1\nflask==2.0.0\n", fake)
    assert [f.dependency.name for f in result.findings] == ["jinja2"]
    assert result.findings[0].advisories[0].id == "PYSEC-1"
    assert [d.name for d in result.clean] == ["flask"]
    assert result.blind_spots == []


def test_unpinned_is_a_blind_spot_and_never_queried():
    fake = FakeOSV({}, {})
    result = run("requirements.txt", "django>=2.0\nflask==2.0.0\n", fake)
    assert [b.reason for b in result.blind_spots] == [UNPINNED_REASON]
    assert "django" in result.blind_spots[0].content
    sent = [q["package"]["name"] for q in fake.batches[0]]
    assert sent == ["flask"]


def test_parser_unsupported_entries_become_blind_spots():
    text = "-r other.txt\npkg @ git+https://x/y.git\n"
    result = run("requirements-dev.txt", text, FakeOSV({}, {}))
    assert len(result.blind_spots) == 2
    assert {b.source_file for b in result.blind_spots} == {"requirements-dev.txt"}
    assert result.blind_spots[0].line_number == 1


def test_nothing_pinned_makes_no_request():
    fake = FakeOSV({}, {})
    result = run("package.json", '{"dependencies": {"a": "^1.0.0"}}', fake)
    assert fake.batches == [] and len(result.blind_spots) == 1


def test_duplicate_packages_are_queried_once():
    lock = ('{"packages": {"node_modules/a": {"version": "1.0.0"}, '
            '"node_modules/b/node_modules/a": {"version": "1.0.0"}}}')
    fake = FakeOSV({("a", "1.0.0"): ["GHSA-1"]},
                   {"GHSA-1": rec("GHSA-1", "a", eco="npm")})
    result = run("package-lock.json", lock, fake)
    assert len(fake.batches[0]) == 1
    assert fake.gets == ["GHSA-1"]          # second one is a cache hit
    assert len(result.findings) == 2         # both locations are reported


def test_withdrawn_advisory_is_not_a_finding():
    fake = FakeOSV({("flask", "2.0.0"): ["PYSEC-9"]},
                   {"PYSEC-9": rec("PYSEC-9", "flask", withdrawn="2026-02-01")})
    result = run("requirements.txt", "flask==2.0.0\n", fake)
    assert result.findings == [] and len(result.clean) == 1


def test_alias_duplicates_merge_and_keep_known_severity():
    fake = FakeOSV(
        {("flask", "2.0.0"): ["PYSEC-2", "GHSA-2"]},
        {"PYSEC-2": rec("PYSEC-2", "flask", severity=None, aliases=["GHSA-2"]),
         "GHSA-2": rec("GHSA-2", "flask", severity="CRITICAL",
                       aliases=["PYSEC-2", "CVE-2026-1"])})
    result = run("requirements.txt", "flask==2.0.0\n", fake)
    advs = result.findings[0].advisories
    assert [a.id for a in advs] == ["GHSA-2"]
    assert advs[0].severity == "critical"


def test_osv_outage_fails_closed():
    def down(request):
        return httpx.Response(503)
    with pytest.raises(OSVError):
        run("requirements.txt", "flask==2.0.0\n", down)


def test_too_many_advisories_raises_before_fetching(monkeypatch):
    monkeypatch.setattr(scanner, "MAX_ADVISORY_FETCHES", 1)
    fake = FakeOSV({("flask", "2.0.0"): ["A-1", "A-2"]}, {})
    with pytest.raises(OSVError):
        run("requirements.txt", "flask==2.0.0\n", fake)
    assert fake.gets == []


@pytest.mark.parametrize("filename, expected", [
    ("package.json", "package.json"),
    ("../../etc/package-lock.json", "package-lock.json"),
    ("C:\\proj\\requirements-prod.txt", "requirements-prod.txt"),
])
def test_parse_file_dispatches_and_strips_paths(filename, expected):
    text = "{}" if filename.endswith(".json") else ""
    name, _ = parse_file(filename, text)
    assert name == expected


@pytest.mark.parametrize("filename", [
    "setup.py", "notes.txt", "package.json.exe", "", "x" * 300, None,
])
def test_parse_file_rejects_unknown_files(filename):
    with pytest.raises(UnsupportedFileError):
        parse_file(filename, "")
        