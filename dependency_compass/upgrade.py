"""Recommend one upgrade target per vulnerable package.

Candidates are the advisories' fixed versions newer than the installed one,
tried smallest first. The first candidate outside every affected range of
every fixable advisory wins. If any range or version can't be compared, no
recommendation is made: a wrong "upgrade to X" is worse than none.
Advisories with no fix at all can't be resolved by upgrading; they're left
out and the recommendation says how many it covers.
"""
from __future__ import annotations

from dataclasses import dataclass

from dependency_compass.advisory import Advisory, Range
from dependency_compass.models import Ecosystem
from dependency_compass.scanner import Finding
from dependency_compass.versions import major, version_key


@dataclass(frozen=True)
class Upgrade:
    version: str
    fixes: int          # advisories this upgrade resolves
    total: int          # advisories on the package
    major_bump: bool    # crosses a major version: check for breaking changes


def _in_range(key: object, rng: Range, ecosystem: Ecosystem) -> bool | None:
    introduced, fixed, last = rng
    low = None if introduced == "0" else version_key(introduced, ecosystem)
    if introduced != "0" and low is None:
        return None
    if low is not None and key < low:
        return False
    if fixed is not None:
        bound = version_key(fixed, ecosystem)
        return None if bound is None else key < bound
    if last is not None:
        bound = version_key(last, ecosystem)
        return None if bound is None else key <= bound
    return True   # open-ended range


def is_affected(version: str, advisory: Advisory,
                ecosystem: Ecosystem) -> bool | None:
    """True/False, or None when we can't tell (no ranges, unparseable)."""
    key = version_key(version, ecosystem)
    if key is None or not advisory.ranges:
        return None
    for rng in advisory.ranges:
        hit = _in_range(key, rng, ecosystem)
        if hit is None or hit:
            return hit
    return False


def recommend_upgrade(finding: Finding) -> Upgrade | None:
    dep = finding.dependency
    eco = dep.ecosystem
    current = version_key(dep.resolved_version or "", eco)
    fixable = [a for a in finding.advisories if a.fixed_versions]
    if current is None or not fixable:
        return None
    keyed = {v: version_key(v, eco) for a in fixable for v in a.fixed_versions}
    candidates = sorted((k, v) for v, k in keyed.items()
                        if k is not None and k > current)
    for _, candidate in candidates:
        verdicts = [is_affected(candidate, a, eco) for a in fixable]
        if None in verdicts:
            return None
        if not any(verdicts):
            return Upgrade(candidate, len(fixable), len(finding.advisories),
                           major(candidate, eco) != major(dep.resolved_version, eco))
    return None
