from __future__ import annotations

import re
from dataclasses import dataclass

from dependency_compass.models import Ecosystem
from dependency_compass.osv_client import OSVError

MAX_SUMMARY = 200
SEVERITY_LABELS = {"LOW": "low", "MODERATE": "medium",
                   "HIGH": "high", "CRITICAL": "critical"}


@dataclass(frozen=True)
class Advisory:
    id: str
    aliases: tuple[str, ...]
    summary: str
    severity: str
    fixed_versions: tuple[str, ...]
    modified: str
    withdrawn: bool


def _norm(name: str, ecosystem: Ecosystem) -> str:
    if ecosystem is Ecosystem.PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()
    return name


def _severity(record: dict) -> str:
    label = (record.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        return SEVERITY_LABELS.get(label.upper(), "unknown")
    return "unknown"


def _fixed(record: dict, name: str, ecosystem: Ecosystem) -> tuple[str, ...]:
    affected = record["affected"]
    if not isinstance(affected, list):
        raise OSVError("malformed affected list")
    want = _norm(name, ecosystem)
    fixed: set[str] = set()
    matched = False
    for entry in affected:
        pkg = entry.get("package") or {}
        if (pkg.get("ecosystem") != ecosystem.value
                or not isinstance(pkg.get("name"), str)
                or _norm(pkg["name"], ecosystem) != want):
            continue
        matched = True
        for rng in entry.get("ranges") or []:
            for event in rng.get("events") or []:
                if isinstance(event.get("fixed"), str):
                    fixed.add(event["fixed"])
    if not matched:
        raise OSVError("record does not describe the queried package")
    return tuple(sorted(fixed))


def parse_advisory(record: dict, name: str, ecosystem: Ecosystem) -> Advisory:
    try:
        if not isinstance(record["id"], str) or not isinstance(
                record["modified"], str):
            raise OSVError("malformed record id or modified")
        aliases = tuple(a for a in record.get("aliases") or []
                        if isinstance(a, str))
        summary = record.get("summary")
        summary = summary[:MAX_SUMMARY] if isinstance(summary, str) else ""
        return Advisory(record["id"], aliases, summary, _severity(record),
                        _fixed(record, name, ecosystem), record["modified"],
                        bool(record.get("withdrawn")))
    except (KeyError, TypeError, AttributeError) as exc:
        raise OSVError(f"malformed record: {type(exc).__name__}") from exc
