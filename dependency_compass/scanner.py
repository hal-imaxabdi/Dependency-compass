"""Scan pipeline: file text -> parser -> OSV -> parsed advisories."""
from __future__ import annotations

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import PurePosixPath

from dependency_compass.advisory import Advisory
from dependency_compass.advisory_cache import AdvisoryCache
from dependency_compass.kev import KEVEntry, KEVLookup, KEVStatus
from dependency_compass.models import Dependency, Ecosystem, ParseResult
from dependency_compass.osv_client import OSVClient, OSVError, PackageQuery
from dependency_compass.parsers.package_json import parse_package_json
from dependency_compass.parsers.package_lock import parse_package_lock
from dependency_compass.parsers.requirements import parse_requirements

MAX_ADVISORY_FETCHES = 2000   # caps follow-up GETs per scan
MAX_FILENAME_LENGTH = 255
UNPINNED_REASON = "version is a range, not an exact pin; not checked"
KEV_SOURCE = "CISA KEV catalog"
KEV_UNAVAILABLE_REASON = ("KEV catalog unavailable; known-exploited status "
                          "of findings was not checked")
KEV_STALE_REASON = "KEV catalog could not be refreshed; using copy released {}"
_REQUIREMENTS_RE = re.compile(r"[A-Za-z0-9._-]*requirements[A-Za-z0-9._-]*\.txt")


class UnsupportedFileError(ValueError):
    """The uploaded file is not a manifest we know how to parse."""


@dataclass(frozen=True)
class Finding:
    dependency: Dependency
    advisories: tuple[Advisory, ...]
    # Aligned with advisories. None = KEV not checked (never means "not in KEV").
    kev: tuple[KEVEntry | None, ...] | None = None


@dataclass(frozen=True)
class BlindSpot:
    source_file: str
    content: str
    reason: str
    line_number: int | None = None


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    clean: list[Dependency] = field(default_factory=list)
    blind_spots: list[BlindSpot] = field(default_factory=list)
    kev_status: KEVStatus | None = None   # None: no findings to look up


def safe_filename(filename: str) -> str:
    """Keep only the base name; never trust or echo a client path."""
    if not isinstance(filename, str) or len(filename) > MAX_FILENAME_LENGTH:
        raise UnsupportedFileError("invalid file name")
    return PurePosixPath(filename.replace("\\", "/")).name


def _parser_for(name: str) -> Callable[[str, str], ParseResult]:
    if name == "package.json":
        return parse_package_json
    if name == "package-lock.json":
        return parse_package_lock
    if _REQUIREMENTS_RE.fullmatch(name):
        return parse_requirements
    raise UnsupportedFileError(
        "unsupported file; expected *requirements*.txt, package.json "
        "or package-lock.json")


def check_filename(filename: str) -> str:
    """Return the safe base name if we can parse it; raise otherwise."""
    name = safe_filename(filename)
    _parser_for(name)
    return name


def parse_file(filename: str, text: str) -> tuple[str, ParseResult]:
    """Pick a parser by file name. Returns (safe base name, result)."""
    name = safe_filename(filename)
    return name, _parser_for(name)(text, name)


def _key(dep: Dependency) -> tuple[str, Ecosystem, str]:
    return (dep.name, dep.ecosystem, dep.resolved_version or "")


def _dedupe(advisories: Iterable[Advisory]) -> tuple[Advisory, ...]:
    """Drop withdrawn records and alias duplicates (e.g. GHSA + PYSEC)."""
    kept: list[Advisory] = []
    seen: set[str] = set()
    # Prefer the copy that has a severity label when two records alias.
    for adv in sorted(advisories, key=lambda a: (a.severity == "unknown", a.id)):
        names = {adv.id, *adv.aliases}
        if adv.withdrawn or names & seen:
            continue
        seen |= names
        kept.append(adv)
    return tuple(sorted(kept, key=lambda a: a.id))


def _add_kev(result: ScanResult, source_file: str, kev: KEVLookup) -> None:
    """Mark findings with KEV entries; report it if KEV couldn't be used."""
    if not result.findings:
        return
    snapshot = kev.get()
    result.kev_status = snapshot.status
    catalog = snapshot.catalog
    if catalog is None:
        result.blind_spots.append(BlindSpot(
            source_file, KEV_SOURCE, KEV_UNAVAILABLE_REASON))
        return
    if snapshot.status is KEVStatus.STALE:
        result.blind_spots.append(BlindSpot(
            source_file, KEV_SOURCE, KEV_STALE_REASON.format(catalog.released)))
    result.findings = [
        Finding(f.dependency, f.advisories,
                tuple(catalog.match(a) for a in f.advisories))
        for f in result.findings]


def scan(parsed: ParseResult, source_file: str, client: OSVClient,
         cache: AdvisoryCache, kev: KEVLookup) -> ScanResult:
    """Check every pinned dependency; report everything we could not check.

    Fails closed: any OSV problem raises OSVError, never a partial result.
    A KEV outage doesn't abort the scan; it leaves Finding.kev as None and
    adds a blind spot.
    """
    result = ScanResult(blind_spots=[
        BlindSpot(source_file, u.content, u.reason, u.line_number)
        for u in parsed.unsupported])
    pinned: list[Dependency] = []
    for dep in parsed.dependencies:
        if dep.resolved_version is None:
            result.blind_spots.append(BlindSpot(
                dep.source_file, f"{dep.name} {dep.version_spec}".strip(),
                UNPINNED_REASON))
        else:
            pinned.append(dep)

    keys = list(dict.fromkeys(_key(d) for d in pinned))   # dedupe, keep order
    if not keys:
        return result
    ids_per_key = dict(zip(keys, client.query_batch(
        [PackageQuery(*k) for k in keys])))

    fetches = {(vid, k[0], k[1]) for k, ids in ids_per_key.items() for vid in ids}
    if len(fetches) > MAX_ADVISORY_FETCHES:
        raise OSVError("too many advisories to fetch in one scan")

    for dep in pinned:
        ids = ids_per_key[_key(dep)]
        advisories = _dedupe(cache.get(v, dep.name, dep.ecosystem) for v in ids)
        if advisories:
            result.findings.append(Finding(dep, advisories))
        else:
            result.clean.append(dep)
    _add_kev(result, source_file, kev)
    return result
