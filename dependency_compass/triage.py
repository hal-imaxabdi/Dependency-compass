"""Triage ranking: order findings by what to fix first, and say why.

Findings are compared rule by rule; a later rule only breaks ties left by
the earlier ones. A package with several advisories ranks by its worst one.

1. Known exploited: a finding with any advisory in CISA KEV ranks first.
   If KEV could not be checked, the finding ranks as not-in-KEV and its
   reasons say the status is unknown (the scan also reports a blind spot).
2. Severity: critical > high > unknown > medium > low. Unknown sits above
   medium on purpose: missing data is ranked cautiously, not optimistically.
3. Production before dev. package.json / package-lock.json say which;
   for requirements files it is inferred from the file name.
4. Direct before transitive: a direct dependency you can upgrade yourself.
5. Fix availability: every advisory has a fix > only some do (partial) > none.
   The reason names one upgrade target when upgrade.py can compute it safely.
6. Tie-break by package name, then version, so the order is deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from dependency_compass.kev import KEVEntry
from dependency_compass.models import Dependency, Ecosystem
from dependency_compass.scanner import Finding
from dependency_compass.upgrade import Upgrade, recommend_upgrade

MAX_LISTED_CVES = 3
SEVERITY_ORDER = {"critical": 0, "high": 1, "unknown": 2,
                  "medium": 3, "low": 4}


class FixState(int, Enum):   # value is the rule 5 sort position
    ALL = 0
    PARTIAL = 1
    NONE = 2


@dataclass(frozen=True)
class RankedFinding:
    rank: int                 # 1 = fix first
    finding: Finding
    reasons: tuple[str, ...]  # one per rule 1-5, in rule order
    upgrade: Upgrade | None = None


def worst_severity(finding: Finding) -> str:
    return min((a.severity for a in finding.advisories),
               key=lambda s: SEVERITY_ORDER.get(s, SEVERITY_ORDER["unknown"]))


def fix_state(finding: Finding) -> FixState:
    fixed = sum(1 for a in finding.advisories if a.fixed_versions)
    if fixed == len(finding.advisories):
        return FixState.ALL
    return FixState.PARTIAL if fixed else FixState.NONE


def _kev_entries(finding: Finding) -> list[KEVEntry]:
    return [e for e in finding.kev or () if e is not None]


def _sort_key(finding: Finding) -> tuple:
    dep = finding.dependency
    return (not _kev_entries(finding),
            SEVERITY_ORDER.get(worst_severity(finding), SEVERITY_ORDER["unknown"]),
            dep.is_dev, not dep.is_direct, fix_state(finding),
            dep.name, dep.resolved_version or "")


def _kev_reason(finding: Finding) -> str:
    if finding.kev is None:
        return "KEV status unknown: catalog unavailable, exploitation not checked"
    entries = _kev_entries(finding)
    if not entries:
        return "not in CISA KEV (no known active exploitation)"
    cves = sorted({e.cve_id for e in entries})
    listed = ", ".join(cves[:MAX_LISTED_CVES])
    if len(cves) > MAX_LISTED_CVES:
        listed += f" (+{len(cves) - MAX_LISTED_CVES} more)"
    reason = f"in CISA KEV: actively exploited ({listed})"
    if any(e.known_ransomware for e in entries):
        reason += "; used in ransomware campaigns"
    return reason


def _severity_reason(finding: Finding) -> str:
    severity = worst_severity(finding)
    count = len(finding.advisories)
    suffix = f" (worst of {count} advisories)" if count > 1 else ""
    if severity == "unknown":
        return f"severity unknown; ranked above medium as a precaution{suffix}"
    return f"{severity} severity{suffix}"


def _dev_reason(dep: Dependency) -> str:
    if dep.ecosystem is Ecosystem.PYPI:
        return ("assumed dev (inferred from file name)" if dep.is_dev
                else "assumed production")
    return "dev dependency" if dep.is_dev else "production dependency"


def _direct_reason(dep: Dependency) -> str:
    if dep.is_direct:
        return "direct dependency: you can upgrade it yourself"
    return "transitive dependency: needs an upgrade of the package that pulls it in"


def _major_note(upgrade: Upgrade) -> str:
    return (" (major version upgrade: check for breaking changes)"
            if upgrade.major_bump else "")


def _fix_reason(finding: Finding, upgrade: Upgrade | None) -> str:
    state = fix_state(finding)
    total = len(finding.advisories)
    if state is FixState.ALL:
        if upgrade is None:
            return "fix available (see each advisory's fixed versions)"
        return (f"fix available: upgrading to {upgrade.version} fixes all "
                f"{total}{_major_note(upgrade)}")
    if state is FixState.PARTIAL:
        fixed = sum(1 for a in finding.advisories if a.fixed_versions)
        if upgrade is None:
            return (f"partial fix: upgrading won't resolve everything "
                    f"({fixed} of {total} advisories have a fix)")
        return (f"partial fix: upgrading won't resolve everything (upgrading "
                f"to {upgrade.version} fixes {fixed} of {total})"
                f"{_major_note(upgrade)}")
    return "no fixed version yet: consider mitigation or replacing it"


def explain(finding: Finding,
            upgrade: Upgrade | None = None) -> tuple[str, ...]:
    dep = finding.dependency
    return (_kev_reason(finding), _severity_reason(finding), _dev_reason(dep),
            _direct_reason(dep), _fix_reason(finding, upgrade))


def rank_findings(findings: list[Finding]) -> list[RankedFinding]:
    """Return findings ordered by the numbered rules above, with reasons."""
    ranked = []
    for i, f in enumerate(sorted(findings, key=_sort_key), 1):
        upgrade = recommend_upgrade(f)
        ranked.append(RankedFinding(i, f, explain(f, upgrade), upgrade))
    return ranked
