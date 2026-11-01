import pytest

from dependency_compass.advisory import Advisory
from dependency_compass.kev import KEVEntry
from dependency_compass.models import Dependency, Ecosystem
from dependency_compass.scanner import Finding
from dependency_compass.triage import (
    FixState, explain, fix_state, rank_findings, worst_severity,
)


def adv(vid="GHSA-1", severity="high", fixed=("2.0.0",)):
    return Advisory(vid, (), "", severity, tuple(fixed),
                    "2026-01-01T00:00:00Z", False)


def kev_entry(cve="CVE-2024-0001", ransomware=False):
    return KEVEntry(cve, "", "2024-05-01", "2024-05-22", ransomware)


def finding(name="pkg", advisories=None, kev="unset", eco=Ecosystem.NPM,
            is_dev=False, is_direct=True, version="1.0.0"):
    advisories = tuple(advisories or [adv()])
    if kev == "unset":   # checked, nothing in KEV
        kev = tuple(None for _ in advisories)
    dep = Dependency(name, eco, version, version, "package-lock.json",
                     is_direct=is_direct, is_dev=is_dev)
    return Finding(dep, advisories, kev)


def order(*findings):
    return [r.finding.dependency.name for r in rank_findings(list(findings))]


# --- one test per rule: the pair differs only in that rule ----------------

def test_rule1_kev_beats_higher_severity():
    exploited = finding("a", [adv(severity="low")], kev=(kev_entry(),))
    critical = finding("b", [adv(severity="critical")])
    assert order(critical, exploited) == ["a", "b"]


def test_rule2_severity_order_with_unknown_above_medium():
    fs = [finding(s, [adv(severity=s)])
          for s in ["low", "medium", "unknown", "high", "critical"]]
    assert order(*fs) == ["critical", "high", "unknown", "medium", "low"]


def test_rule3_production_before_dev():
    assert order(finding("a", is_dev=True), finding("b")) == ["b", "a"]


def test_rule4_direct_before_transitive():
    assert order(finding("a", is_direct=False), finding("b")) == ["b", "a"]


def test_rule5_all_fixed_then_partial_then_none():
    none = finding("none", [adv(fixed=())])
    partial = finding("partial", [adv("A"), adv("B", fixed=())])
    full = finding("all", [adv("A"), adv("B")])
    assert order(none, partial, full) == ["all", "partial", "none"]


def test_rule6_tie_break_is_deterministic():
    fs = [finding("b", version="1.0.0"), finding("a", version="2.0.0"),
          finding("a", version="1.0.0")]
    ranked = rank_findings(fs)
    assert [(r.finding.dependency.name, r.finding.dependency.resolved_version)
            for r in ranked] == [("a", "1.0.0"), ("a", "2.0.0"), ("b", "1.0.0")]
    assert [r.rank for r in ranked] == [1, 2, 3]


def test_earlier_rule_wins_over_later_ones():
    # prod + transitive + no fix still beats dev + direct + fixed (rule 3).
    prod = finding("prod", [adv(fixed=())], is_direct=False)
    dev = finding("dev", is_dev=True)
    assert order(dev, prod) == ["prod", "dev"]


# --- worst advisory, KEV unknown --------------------------------------------

def test_worst_advisory_decides_severity():
    f = finding(advisories=[adv("A", "low"), adv("B", "critical"),
                            adv("C", "unknown")])
    assert worst_severity(f) == "critical"
    assert "worst of 3 advisories" in explain(f)[1]


def test_unexpected_severity_label_is_treated_as_unknown():
    f = finding(advisories=[adv(severity="bogus")])
    assert order(finding("m", [adv(severity="medium")]),
                 finding("x", [adv(severity="bogus")])) == ["x", "m"]
    assert worst_severity(f) == "bogus"


def test_kev_unknown_ranks_as_not_in_kev_and_says_so():
    unknown = finding("unknown", [adv(severity="low")], kev=None)
    critical = finding("critical", [adv(severity="critical")])
    assert order(unknown, critical) == ["critical", "unknown"]
    assert "KEV status unknown" in explain(unknown)[0]


# --- reasons ------------------------------------------------------------------

def test_reasons_follow_rule_order():
    f = finding(kev=(kev_entry(ransomware=True),))
    reasons = explain(f)
    assert len(reasons) == 5
    assert reasons[0].startswith("in CISA KEV") and "CVE-2024-0001" in reasons[0]
    assert "ransomware" in reasons[0]
    assert reasons[1:] == ("high severity", "production dependency",
                           "direct dependency: you can upgrade it yourself",
                           "fix available (see each advisory's fixed versions)")


def test_kev_reason_caps_listed_cves():
    entries = tuple(kev_entry(f"CVE-2024-000{i}") for i in range(5))
    f = finding(advisories=[adv(f"A{i}") for i in range(5)], kev=entries)
    assert "(+2 more)" in explain(f)[0]


@pytest.mark.parametrize("is_dev, expected", [
    (True, "assumed dev (inferred from file name)"),
    (False, "assumed production"),
])
def test_requirements_dev_reason_is_marked_as_assumed(is_dev, expected):
    f = finding(eco=Ecosystem.PYPI, is_dev=is_dev)
    assert explain(f)[2] == expected


def test_partial_and_none_fix_reasons():
    partial = finding(advisories=[adv("A"), adv("B", fixed=())])
    assert fix_state(partial) is FixState.PARTIAL
    assert explain(partial)[4].startswith("partial fix: upgrading won't")
    assert "1 of 2" in explain(partial)[4]
    none = finding(advisories=[adv(fixed=())])
    assert explain(none)[4].startswith("no fixed version yet")


def test_transitive_reason():
    assert explain(finding(is_direct=False))[3].startswith("transitive")


def test_empty_input():
    assert rank_findings([]) == []


def test_fix_reason_names_the_upgrade():
    a = Advisory("A", (), "", "high", ("2.0.0",), "2026-01-01", False,
                 (("0", "2.0.0", None),))
    ranked = rank_findings([finding(advisories=[a])])[0]
    assert ranked.upgrade.version == "2.0.0"
    assert ranked.reasons[4] == ("fix available: upgrading to 2.0.0 fixes all 1 "
                                 "(major version upgrade: check for breaking changes)")
