from dependency_compass.advisory import Advisory
from dependency_compass.models import Dependency, Ecosystem
from dependency_compass.scanner import Finding
from dependency_compass.upgrade import is_affected, recommend_upgrade


def adv(vid, ranges, fixed=None):
    if fixed is None:
        fixed = tuple(f for _, f, _ in ranges if f)
    return Advisory(vid, (), "", "high", tuple(fixed), "2026-01-01", False,
                    tuple(ranges))


def finding(version, *advisories, eco=Ecosystem.PYPI):
    dep = Dependency("django", eco, version, version, "requirements.txt")
    return Finding(dep, advisories, None)


# Django-like: each advisory fixed on several release branches.
A = adv("A", [("0", "3.2.13", None), ("4.0", "4.0.4", None)])
B = adv("B", [("0", "3.2.19", None), ("4.0", "4.1.9", None)])
C = adv("C", [("0", "4.2.26", None)])   # no 3.2 fix: forces a major upgrade


def test_smallest_version_fixing_everything():
    up = recommend_upgrade(finding("3.2.0", A, B))
    assert (up.version, up.fixes, up.total, up.major_bump) == ("3.2.19", 2, 2, False)


def test_branch_without_fix_forces_major_upgrade():
    up = recommend_upgrade(finding("3.2.0", A, B, C))
    assert up.version == "4.2.26" and up.major_bump is True


def test_fixed_version_inside_another_range_is_skipped():
    # 4.0.4 fixes A but is still affected by B; 4.1.9 fixes both.
    up = recommend_upgrade(finding("4.0.0", A, B))
    assert up.version == "4.1.9"


def test_partial_counts_only_fixable_advisories():
    nofix = adv("N", [("0", None, None)], fixed=())
    up = recommend_upgrade(finding("3.2.0", A, nofix))
    assert (up.version, up.fixes, up.total) == ("3.2.13", 1, 2)


def test_last_affected_is_inclusive():
    a = adv("L", [("0", None, "1.4.0")], fixed=("1.4.0", "1.5.0"))
    assert is_affected("1.4.0", a, Ecosystem.PYPI) is True
    assert recommend_upgrade(finding("1.0.0", a)).version == "1.5.0"


def test_unknown_ranges_give_no_recommendation():
    assert recommend_upgrade(finding("3.2.0", adv("X", [], fixed=("3.2.13",)))) is None
    bad = adv("Y", [("weird!", "3.2.13", None)])
    assert recommend_upgrade(finding("3.2.0", bad)) is None


def test_unparseable_current_version_gives_none():
    assert recommend_upgrade(finding("not-a-version", A)) is None


def test_no_candidate_newer_than_current():
    assert recommend_upgrade(finding("9.0.0", A)) is None


def test_npm_semver():
    a = adv("N", [("0", "4.17.21", None)])
    up = recommend_upgrade(finding("4.17.4", a, eco=Ecosystem.NPM))
    assert up.version == "4.17.21" and up.major_bump is False
