"""Command-line interface.

Usage:
    python -m dependency_compass scan FILE [--json] [--fail-on LEVEL] [--strict]

Exit codes (checked in this order; the first that applies wins):
    2  usage error, or FILE is unreadable, too large, not UTF-8, or unsupported
    3  OSV could not be queried; no report is produced (fail closed)
    1  a finding is in CISA KEV, or its worst severity is at/above --fail-on
       (default "high"; unknown severity counts as failing at "high" and above)
    4  incomplete: KEV was unavailable while there were findings (one of them
       could be exploited), or --strict and there are blind spots
    0  everything we could check was checked and nothing reached the threshold
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from dependency_compass.advisory_cache import AdvisoryCache
from dependency_compass.kev import KEVClient, KEVLookup, KEVStatus
from dependency_compass.osv_client import OSVClient, OSVError
from dependency_compass.report import render_text, to_dict
from dependency_compass.scanner import ScanResult, UnsupportedFileError, parse_file, scan
from dependency_compass.triage import (
    SEVERITY_ORDER, RankedFinding, rank_findings, worst_severity,
)

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE, EXIT_UNAVAILABLE, EXIT_INCOMPLETE = 0, 1, 2, 3, 4
MAX_FILE_BYTES = 5 * 1024 * 1024
# A finding fails when its worst severity's SEVERITY_ORDER is <= this.
FAIL_ON = {"critical": SEVERITY_ORDER["critical"], "high": SEVERITY_ORDER["unknown"],
           "medium": SEVERITY_ORDER["medium"], "low": SEVERITY_ORDER["low"],
           "any": max(SEVERITY_ORDER.values())}


class InputError(Exception):
    """The local file can't be used; message is safe to print."""


@dataclass
class Services:
    osv: OSVClient
    cache: AdvisoryCache
    kev: KEVLookup


def default_services() -> Services:
    osv = OSVClient()
    return Services(osv, AdvisoryCache(osv), KEVLookup(KEVClient()))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dependency-compass",
        description="Rank dependency vulnerabilities by what to fix first.")
    sub = parser.add_subparsers(dest="command", required=True)
    s = sub.add_parser("scan", help="scan a requirements*.txt, package.json "
                                    "or package-lock.json file")
    s.add_argument("file")
    s.add_argument("--json", action="store_true", help="print JSON instead of text")
    s.add_argument("--fail-on", choices=list(FAIL_ON), default="high",
                   help="exit 1 if any finding is at/above this severity "
                        "(KEV findings always fail; default: high)")
    s.add_argument("--strict", action="store_true",
                   help="exit 4 if anything could not be checked")
    return parser


def read_manifest(path: str) -> tuple[str, str]:
    """Return (base name, text). Reads at most MAX_FILE_BYTES + 1 bytes."""
    p = Path(path)
    try:
        with p.open("rb") as fh:
            data = fh.read(MAX_FILE_BYTES + 1)
    except OSError:
        raise InputError("cannot read file") from None
    if len(data) > MAX_FILE_BYTES:
        raise InputError(f"file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    try:
        return p.name, data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InputError("file is not valid UTF-8") from None


def _severity_fails(ranked: RankedFinding, fail_on: str) -> bool:
    severity = worst_severity(ranked.finding)
    return SEVERITY_ORDER.get(severity, SEVERITY_ORDER["unknown"]) <= FAIL_ON[fail_on]


def exit_code(result: ScanResult, ranked: list[RankedFinding],
              fail_on: str, strict: bool) -> int:
    for r in ranked:
        if any(e is not None for e in r.finding.kev or ()) \
                or _severity_fails(r, fail_on):
            return EXIT_FINDINGS
    if result.kev_status is KEVStatus.UNAVAILABLE and ranked:
        return EXIT_INCOMPLETE
    if strict and result.blind_spots:
        return EXIT_INCOMPLETE
    return EXIT_OK


def main(argv: list[str] | None = None, services: Services | None = None,
         stdout: TextIO = sys.stdout, stderr: TextIO = sys.stderr) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:   # argparse: --help -> 0, bad usage -> 2
        return exc.code if isinstance(exc.code, int) else EXIT_USAGE
    try:
        filename, text = read_manifest(args.file)
        name, parsed = parse_file(filename, text)
    except (InputError, UnsupportedFileError) as exc:
        print(f"error: {exc}", file=stderr)
        return EXIT_USAGE
    services = services or default_services()
    try:
        result = scan(parsed, name, services.osv, services.cache, services.kev)
    except OSVError:
        print("error: could not query OSV; no results reported (fail closed)",
              file=stderr)
        return EXIT_UNAVAILABLE
    ranked = rank_findings(result.findings)
    data = to_dict(result, ranked, name)
    if args.json:
        print(json.dumps(data, indent=2), file=stdout)
    else:
        print(render_text(data), end="", file=stdout)
    return exit_code(result, ranked, args.fail_on, args.strict)
