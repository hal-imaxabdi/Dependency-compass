import io
import json

import httpx
import pytest

from dependency_compass import cli
from dependency_compass.advisory_cache import AdvisoryCache
from dependency_compass.cli import Services, main
from dependency_compass.kev import KEVCatalog, KEVEntry, KEVSnapshot, KEVStatus
from dependency_compass.osv_client import OSVClient

ENTRY = KEVEntry("CVE-2024-0001", "", "2024-05-01", "2024-05-22", False)
CATALOG = KEVCatalog({ENTRY.cve_id: ENTRY}, "2026-11-01")


def rec(vid, name, severity="HIGH", aliases=()):
    return {"id": vid, "modified": "2026-01-01T00:00:00Z",
            "aliases": list(aliases),
            "summary": "bad thing",
            "database_specific": {"severity": severity},
            "affected": [{"package": {"name": name, "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM", "events": [
                              {"introduced": "0"}, {"fixed": "9.9.9"}]}]}]}


class FakeKEV:
    def __init__(self, status=KEVStatus.OK):
        self.snapshot = KEVSnapshot(
            None if status is KEVStatus.UNAVAILABLE else CATALOG, status)

    def get(self):
        return self.snapshot


def services(records=None, kev_status=KEVStatus.OK, down=False):
    """records: {package name: [OSV record, ...]}"""
    records = records or {}
    by_id = {r["id"]: r for rs in records.values() for r in rs}

    def handler(request):
        if down:
            return httpx.Response(503)
        if request.method == "POST":
            qs = json.loads(request.content)["queries"]
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": r["id"]} for r in
                           records.get(q["package"]["name"], [])]} for q in qs]})
        return httpx.Response(200, json=by_id[request.url.path.rsplit("/", 1)[1]])

    osv = OSVClient(transport=httpx.MockTransport(handler), sleep=lambda s: None)
    return Services(osv, AdvisoryCache(osv), FakeKEV(kev_status))


def run(tmp_path, text, *args, name="requirements.txt", svc=None):
    path = tmp_path / name
    path.write_text(text)
    out, err = io.StringIO(), io.StringIO()
    code = main(["scan", str(path), *args], svc or services(), out, err)
    return code, out.getvalue(), err.getvalue()


# --- exit codes ------------------------------------------------------------

def test_exit_0_when_nothing_found(tmp_path):
    code, out, _ = run(tmp_path, "flask==2.0.0\n")
    assert code == 0
    assert "No known vulnerabilities in 1 checked package" in out


def test_exit_1_on_high_finding(tmp_path):
    svc = services({"jinja2": [rec("PYSEC-1", "jinja2")]})
    code, out, _ = run(tmp_path, "jinja2==2.4.1\n", svc=svc)
    assert code == 1 and "#1  jinja2 2.4.1" in out


@pytest.mark.parametrize("severity, fail_on, expected", [
    ("MODERATE", "high", 0),
    ("MODERATE", "medium", 1),
    ("HIGH", "critical", 0),
    ("LOW", "any", 1),
    (None, "high", 1),        # unknown severity fails at high
    (None, "critical", 0),
])
def test_fail_on_threshold(tmp_path, severity, fail_on, expected):
    svc = services({"jinja2": [rec("PYSEC-1", "jinja2", severity)]})
    code, _, _ = run(tmp_path, "jinja2==2.4.1\n", "--fail-on", fail_on, svc=svc)
    assert code == expected


def test_kev_finding_fails_even_below_threshold(tmp_path):
    svc = services({"jinja2": [rec("PYSEC-1", "jinja2", "LOW",
                                   aliases=["CVE-2024-0001"])]})
    code, out, _ = run(tmp_path, "jinja2==2.4.1\n", "--fail-on", "critical",
                       svc=svc)
    assert code == 1 and "[KEV]" in out


def test_advisories_listed_worst_first(tmp_path):
    svc = services({"jinja2": [rec("A-1", "jinja2", "LOW"),
                               rec("B-1", "jinja2", "MODERATE",
                                   aliases=["CVE-2024-0001"]),
                               rec("C-1", "jinja2", "CRITICAL")]})
    _, out, _ = run(tmp_path, "jinja2==2.4.1\n", "--json", svc=svc)
    ids = [a["id"] for a in json.loads(out)["findings"][0]["advisories"]]
    assert ids == ["B-1", "C-1", "A-1"]


def test_exit_2_on_usage_error(capsys):
    assert main(["scan"], services()) == 2


def test_exit_2_on_unsupported_file(tmp_path):
    code, _, err = run(tmp_path, "x", name="setup.py")
    assert code == 2 and err.startswith("error: unsupported file")


def test_exit_2_on_missing_file_without_echoing_path(tmp_path):
    err = io.StringIO()
    path = tmp_path / "requirements.txt"
    assert main(["scan", str(path)], services(), io.StringIO(), err) == 2
    assert err.getvalue() == "error: cannot read file\n"


def test_exit_2_on_non_utf8(tmp_path):
    path = tmp_path / "requirements.txt"
    path.write_bytes(b"\xff\xfe\x00bad")
    err = io.StringIO()
    assert main(["scan", str(path)], services(), io.StringIO(), err) == 2
    assert "UTF-8" in err.getvalue()


def test_exit_2_on_oversized_file(tmp_path, monkeypatch):
    monkeypatch.setattr(cli, "MAX_FILE_BYTES", 10)
    code, _, err = run(tmp_path, "flask==2.0.0\n" * 5)
    assert code == 2 and "larger than" in err


def test_exit_3_when_osv_down_and_no_report(tmp_path):
    code, out, err = run(tmp_path, "flask==2.0.0\n", svc=services(down=True))
    assert code == 3 and out == ""
    assert "fail closed" in err and "Traceback" not in err


def test_exit_4_when_kev_unavailable_with_findings(tmp_path):
    svc = services({"jinja2": [rec("PYSEC-1", "jinja2", "LOW")]},
                   kev_status=KEVStatus.UNAVAILABLE)
    code, out, _ = run(tmp_path, "jinja2==2.4.1\n", svc=svc)
    assert code == 4 and "KEV status unknown" in out


def test_findings_beat_incomplete(tmp_path):
    svc = services({"jinja2": [rec("PYSEC-1", "jinja2", "CRITICAL")]},
                   kev_status=KEVStatus.UNAVAILABLE)
    assert run(tmp_path, "jinja2==2.4.1\n", svc=svc)[0] == 1


def test_blind_spots_exit_4_only_with_strict(tmp_path):
    text = "flask>=2.0\n"
    code, out, _ = run(tmp_path, text)
    assert code == 0 and "NOT checked" in out
    assert run(tmp_path, text, "--strict")[0] == 4


def test_help_exits_0(capsys):
    assert main(["--help"], services()) == 0


# --- output ----------------------------------------------------------------

def test_json_output(tmp_path):
    svc = services({"jinja2": [rec("PYSEC-1", "jinja2", aliases=["CVE-2024-0001"])]})
    code, out, _ = run(tmp_path, "jinja2==2.4.1\nflask>=1\n", "--json", svc=svc)
    data = json.loads(out)
    assert code == 1
    assert data["schema_version"] == 1
    assert data["summary"] == {"findings": 1, "in_kev": 1, "clean": 0,
                               "blind_spots": 1, "kev_status": "ok"}
    f = data["findings"][0]
    assert (f["rank"], f["package"], f["in_kev"], f["fix"]) == (1, "jinja2", True, "all")
    assert f["advisories"][0]["kev"]["cve_id"] == "CVE-2024-0001"
    assert f["advisories"][0]["fixed_versions"] == ["9.9.9"]


def test_only_base_name_is_printed(tmp_path):
    code, out, _ = run(tmp_path, "flask==2.0.0\n", "--json")
    assert json.loads(out)["file"] == "requirements.txt"
    assert str(tmp_path) not in out
