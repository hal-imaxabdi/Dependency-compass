from __future__ import annotations

import re
from dataclasses import dataclass

from dependency_compass.models import Ecosystem
from dependency_compass.osv_client import OSVError

MAX_SUMMARY = 200
MAX_VERSION = 128
MAX_RANGES = 1000
VERSION_RANGE_TYPES = frozenset({"ECOSYSTEM", "SEMVER"})
# (introduced, fixed, last_affected); introduced "0" means "from the start".
Range = tuple[str, str | None, str | None]
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
    ranges: tuple[Range, ...] = ()   # empty = unknown, never "unaffected"


def _norm(name: str, ecosystem: Ecosystem) -> str:
    if ecosystem is Ecosystem.PYPI:
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem is Ecosystem.PACKAGIST:
        return name.lower()   # Composer package names are case-insensitive
    return name


def _severity(record: dict) -> str:
    label = (record.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        return SEVERITY_LABELS.get(label.upper(), "unknown")
    return "unknown"


def _range_events(events: list) -> list[Range]:
    """Pair OSV events into (introduced, fixed, last_affected) ranges."""
    ranges: list[Range] = []
    start: str | None = None
    for event in events:
        if not isinstance(event, dict):
            raise OSVError("malformed range event")
        for key, value in event.items():
            if key != "limit" and (not isinstance(value, str)
                                   or len(value) > MAX_VERSION):
                raise OSVError("malformed range version")
        if "introduced" in event:
            if start is not None:
                ranges.append((start, None, None))   # still open
            start = event["introduced"]
        elif start is not None and "fixed" in event:
            ranges.append((start, event["fixed"], None))
            start = None
        elif start is not None and "last_affected" in event:
            ranges.append((start, None, event["last_affected"]))
            start = None
        # "limit" is ignored: the range stays open, which is the safe side.
    if start is not None:
        ranges.append((start, None, None))
    return ranges


def _affected(record: dict, name: str,
              ecosystem: Ecosystem) -> tuple[tuple[str, ...], tuple[Range, ...]]:
    """Fixed versions and version ranges for the queried package only.

    GIT ranges are skipped: their events are commit hashes, not versions.
    """
    affected = record["affected"]
    if not isinstance(affected, list):
        raise OSVError("malformed affected list")
    want = _norm(name, ecosystem)
    fixed: set[str] = set()
    ranges: list[Range] = []
    matched = False
    for entry in affected:
        pkg = entry.get("package") or {}
        if (pkg.get("ecosystem") != ecosystem.value
                or not isinstance(pkg.get("name"), str)
                or _norm(pkg["name"], ecosystem) != want):
            continue
        matched = True
        for rng in entry.get("ranges") or []:
            if rng.get("type") not in VERSION_RANGE_TYPES:
                continue
            found = _range_events(rng.get("events") or [])
            ranges.extend(found)
            fixed.update(f for _, f, _ in found if f is not None)
    if not matched:
        raise OSVError("record does not describe the queried package")
    if len(ranges) > MAX_RANGES:
        raise OSVError("record has too many ranges")
    return tuple(sorted(fixed)), tuple(ranges)


def parse_advisory(record: dict, name: str, ecosystem: Ecosystem) -> Advisory:
    try:
        if not isinstance(record["id"], str) or not isinstance(
                record["modified"], str):
            raise OSVError("malformed record id or modified")
        aliases = tuple(a for a in record.get("aliases") or []
                        if isinstance(a, str))
        summary = record.get("summary")
        summary = summary[:MAX_SUMMARY] if isinstance(summary, str) else ""
        fixed, ranges = _affected(record, name, ecosystem)
        return Advisory(record["id"], aliases, summary, _severity(record),
                        fixed, record["modified"],
                        bool(record.get("withdrawn")), ranges)
    except (KeyError, TypeError, AttributeError) as exc:
        raise OSVError(f"malformed record: {type(exc).__name__}") from exc
