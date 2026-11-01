"""Turn a scan into a JSON-ready dict and a readable text report.

All untrusted text (package names, summaries, blind-spot content) passes
through clean_text once, in to_dict; render_text only reads that dict.
"""
from __future__ import annotations

import re

from dependency_compass.kev import KEVEntry
from dependency_compass.scanner import BlindSpot, ScanResult
from dependency_compass.triage import (
    SEVERITY_ORDER, RankedFinding, fix_state, worst_severity,
)

SCHEMA_VERSION = 1
MAX_TEXT = 200
MAX_LISTED_FIXES = 5
LOCKFILE_HINT = ("package.json only lists version ranges. Scan package-lock.json "
                 "instead: it has the exact installed versions.")
# C0/C1 controls (incl. ESC for ANSI sequences) and bidi overrides.
_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f-\x9f‎‏‪-‮⁦-⁩]")


def clean_text(value: object, limit: int = MAX_TEXT) -> str:
    """Make untrusted text safe to print: no control chars, bounded length."""
    text = _UNSAFE_RE.sub("", value if isinstance(value, str) else str(value))
    return text if len(text) <= limit else text[:limit] + "…"


def _kev_dict(entry: KEVEntry) -> dict:
    return {"cve_id": entry.cve_id, "name": clean_text(entry.name),
            "date_added": entry.date_added, "due_date": entry.due_date,
            "known_ransomware": entry.known_ransomware}


def _finding_dict(ranked: RankedFinding) -> dict:
    f = ranked.finding
    dep = f.dependency
    kev = f.kev if f.kev is not None else (None,) * len(f.advisories)
    advisories = [{
        "id": clean_text(a.id),
        "aliases": [clean_text(x) for x in a.aliases],
        "summary": clean_text(a.summary),
        "severity": a.severity,
        "fixed_versions": [clean_text(v) for v in a.fixed_versions],
        "in_kev": None if f.kev is None else entry is not None,   # None = unknown
        "kev": _kev_dict(entry) if entry is not None else None,
    } for a, entry in zip(f.advisories, kev)]
    advisories.sort(key=lambda a: (not a["in_kev"], SEVERITY_ORDER.get(
        a["severity"], SEVERITY_ORDER["unknown"]), a["id"]))   # worst first
    in_kev = None if f.kev is None else any(a["in_kev"] for a in advisories)
    up = ranked.upgrade
    upgrade = None if up is None else {
        "version": clean_text(up.version), "fixes": up.fixes,
        "total": up.total, "major_bump": up.major_bump}
    return {"rank": ranked.rank, "package": clean_text(dep.name),
            "version": clean_text(dep.resolved_version or ""),
            "ecosystem": dep.ecosystem.value, "direct": dep.is_direct,
            "dev": dep.is_dev, "in_kev": in_kev,
            "worst_severity": clean_text(worst_severity(f)),
            "fix": fix_state(f).name.lower(),
            "upgrade": upgrade,
            "reasons": [clean_text(r) for r in ranked.reasons],
            "advisories": advisories}


def _blind_spot_dict(b: BlindSpot) -> dict:
    return {"file": clean_text(b.source_file), "line": b.line_number,
            "content": clean_text(b.content), "reason": clean_text(b.reason)}


def _hint(result: ScanResult, source_file: str) -> str | None:
    if source_file == "package.json" and result.blind_spots:
        return LOCKFILE_HINT
    return None


def to_dict(result: ScanResult, ranked: list[RankedFinding],
            source_file: str) -> dict:
    findings = [_finding_dict(r) for r in ranked]
    return {
        "schema_version": SCHEMA_VERSION,
        "file": clean_text(source_file),
        "summary": {
            "findings": len(findings),
            "in_kev": sum(1 for f in findings if f["in_kev"]),
            "clean": len(result.clean),
            "blind_spots": len(result.blind_spots),
            "kev_status": result.kev_status.value if result.kev_status else None,
        },
        "hint": _hint(result, source_file),
        "findings": findings,
        "blind_spots": [_blind_spot_dict(b) for b in result.blind_spots],
        "clean": [{"package": clean_text(d.name),
                   "version": clean_text(d.resolved_version or ""),
                   "ecosystem": d.ecosystem.value} for d in result.clean],
    }


def _headline(data: dict) -> str:
    s = data["summary"]
    if s["findings"]:
        kev = f" ({s['in_kev']} in CISA KEV)" if s["in_kev"] else ""
        return (f"{s['findings']} vulnerable package(s){kev} · "
                f"{s['clean']} with no known advisories · "
                f"{s['blind_spots']} not checked")
    if s["blind_spots"] and not s["clean"]:
        return (f"Nothing could be checked: {s['blind_spots']} item(s) were "
                f"NOT checked (see blind spots).")
    if s["blind_spots"]:
        return (f"No known vulnerabilities in the {s['clean']} package(s) we "
                f"could check, but {s['blind_spots']} item(s) were NOT checked "
                f"(see blind spots).")
    return f"No known vulnerabilities in {s['clean']} checked package(s)."


def _fixes(adv: dict) -> str:
    fixes = adv["fixed_versions"]
    if not fixes:
        return "no fix yet"
    more = f" (+{len(fixes) - MAX_LISTED_FIXES} more)" \
        if len(fixes) > MAX_LISTED_FIXES else ""
    return "fixed in " + ", ".join(fixes[:MAX_LISTED_FIXES]) + more


def upgrade_line(up: dict) -> str:
    covers = f"all {up['total']}" if up["fixes"] == up["total"] \
        else f"{up['fixes']} of {up['total']}"
    major = " (major version upgrade: check for breaking changes)" \
        if up["major_bump"] else ""
    return f"Upgrade to {up['version']}: fixes {covers} advisories{major}"


def _finding_lines(f: dict) -> list[str]:
    scope = "dev" if f["dev"] else "prod"
    kind = "direct" if f["direct"] else "transitive"
    lines = [f"#{f['rank']}  {f['package']} {f['version']}  "
             f"[{f['ecosystem']} · {scope} · {kind}]"]
    if f["upgrade"]:
        lines.append(f"    → {upgrade_line(f['upgrade'])}")
    for a in f["advisories"]:
        kev = "  [KEV]" if a["in_kev"] else ""
        summary = f"  {a['summary']}" if a["summary"] else ""
        lines.append(f"    - {a['id']} ({a['severity']}){kev}{summary}")
        lines.append(f"      {_fixes(a)}")
    lines.append("    Why it ranks here:")
    lines.extend(f"      · {r}" for r in f["reasons"])
    return lines


def _blind_spot_line(b: dict) -> str:
    where = f"{b['file']}:{b['line']}" if b["line"] is not None else b["file"]
    content = f"  {b['content']}" if b["content"] else ""
    return f"  - {where}{content}: {b['reason']}"


def render_text(data: dict) -> str:
    lines = [f"Dependency Compass: {data['file']}", _headline(data)]
    if data["hint"]:
        lines.append(f"Tip: {data['hint']}")
    lines.append("")
    for f in data["findings"]:
        lines.extend(_finding_lines(f))
        lines.append("")
    if data["blind_spots"]:
        lines.append("Blind spots (not checked):")
        lines.extend(_blind_spot_line(b) for b in data["blind_spots"])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"
