from dependency_compass.advisory import Advisory
from dependency_compass.models import Dependency, Ecosystem
from dependency_compass.report import clean_text, render_text, to_dict
from dependency_compass.scanner import BlindSpot, Finding, ScanResult
from dependency_compass.triage import rank_findings


def scan_result(kev="checked", summary="bad"):
    adv = Advisory("GHSA-1", ("CVE-2024-0001",), summary, "high", ("2.0.0",),
                   "2026-01-01T00:00:00Z", False)
    dep = Dependency("evil\x1b[31mpkg", Ecosystem.NPM, "1.0.0", "1.0.0",
                     "package-lock.json", is_direct=False)
    result = ScanResult(findings=[Finding(dep, (adv,),
                                          (None,) if kev == "checked" else None)])
    result.blind_spots.append(BlindSpot("package.json", "x‮y", "range", None))
    return result


def test_clean_text_strips_controls_and_bidi_and_truncates():
    assert clean_text("a\x1b[2Jb\x00c‮d\n") == "a[2Jbcd"
    assert clean_text("x" * 300) == "x" * 200 + "…"
    assert clean_text(42) == "42"


def test_to_dict_cleans_untrusted_text():
    result = scan_result(summary="\x07ding" + "s" * 300)
    data = to_dict(result, rank_findings(result.findings), "package-lock.json")
    f = data["findings"][0]
    assert f["package"] == "evil[31mpkg"
    assert f["advisories"][0]["summary"].startswith("dings")
    assert len(f["advisories"][0]["summary"]) == 201
    assert data["blind_spots"][0]["content"] == "xy"


def test_kev_checked_vs_unknown_in_json():
    checked = scan_result()
    d = to_dict(checked, rank_findings(checked.findings), "f")
    assert d["findings"][0]["in_kev"] is False
    assert d["findings"][0]["advisories"][0]["in_kev"] is False
    unknown = scan_result(kev=None)
    d = to_dict(unknown, rank_findings(unknown.findings), "f")
    assert d["findings"][0]["in_kev"] is None
    assert d["findings"][0]["advisories"][0]["in_kev"] is None


def test_text_report_has_findings_reasons_and_blind_spots():
    result = scan_result()
    text = render_text(to_dict(result, rank_findings(result.findings),
                               "package-lock.json"))
    assert "\x1b" not in text
    assert "#1  evil[31mpkg 1.0.0  [npm · prod · transitive]" in text
    assert "fixed in 2.0.0" in text
    assert "Why it ranks here:" in text and "transitive dependency" in text
    assert "Blind spots (not checked):" in text
    assert "  - package.json  xy: range" in text


def test_text_never_says_clean_when_blind_spots_exist():
    result = ScanResult(blind_spots=[BlindSpot("r.txt", "a>=1", "range", 1)])
    text = render_text(to_dict(result, [], "r.txt"))
    assert "NOT checked" in text and "r.txt:1" in text


def test_nothing_checked_headline_and_lockfile_hint():
    result = ScanResult(blind_spots=[BlindSpot("package.json", "a ^1.0.0",
                                               "range", None)])
    data = to_dict(result, [], "package.json")
    text = render_text(data)
    assert data["hint"] and "package-lock.json" in data["hint"]
    assert "Nothing could be checked: 1 item(s)" in text
    assert "Tip: package.json only lists version ranges" in text


def test_no_hint_for_lockfile():
    result = ScanResult(blind_spots=[BlindSpot("package-lock.json", "x", "y", None)])
    assert to_dict(result, [], "package-lock.json")["hint"] is None
