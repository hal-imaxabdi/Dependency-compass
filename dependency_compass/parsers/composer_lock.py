"""Parse PHP Composer lockfiles (composer.lock).

composer.lock is JSON with two lists, "packages" and "packages-dev", each
entry holding at least {"name": "vendor/package", "version": "1.2.3"}.
It records exact installed versions but not which packages the project
required directly, so every entry is treated as direct (the same
simplification used for requirements.txt).
"""
from __future__ import annotations

import json
import re

from dependency_compass.models import (
    Dependency, Ecosystem, ParseResult, UnsupportedEntry,
)
from dependency_compass.parsers.package_json import MAX_DEPENDENCIES

MAX_NAME_LENGTH = 214
MAX_VERSION_LENGTH = 128

# Composer names are "vendor/package", lowercase in practice.
# [0-9a-z] (not \w) so Unicode letters and digits never match.
_NAME_RE = re.compile(r"[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*")

# Stable releases only: optional "v", three numbers without leading zeros.
# Prereleases (beta, RC) and branches (dev-main) sort differently in Composer
# than in SemVer, so they become blind spots instead of guesses.
_STABLE_RE = re.compile(r"v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")

_SECTIONS = (
    ("packages", False),
    ("packages-dev", True),
)


def _truncate(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _unsupported(content: str, reason: str) -> UnsupportedEntry:
    return UnsupportedEntry(None, _truncate(content), reason)


def exact_composer_version(value: str) -> str | None:
    """Return 'X.Y.Z' only for an exact stable release, else None."""
    if not isinstance(value, str) or len(value) > MAX_VERSION_LENGTH:
        return None
    match = _STABLE_RE.fullmatch(value.strip())
    if match is None:
        return None
    return ".".join(match.groups())


def parse_composer_lock(text: str, source_file: str = "composer.lock") -> ParseResult:
    result = ParseResult()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        result.unsupported.append(_unsupported("", "invalid or too deeply nested JSON"))
        return result

    if not isinstance(data, dict):
        result.unsupported.append(_unsupported("", "top level of JSON is not an object"))
        return result

    if not any(isinstance(data.get(s), list) for s, _ in _SECTIONS):
        result.unsupported.append(_unsupported(
            "", "unrecognized lockfile layout; nothing was analyzed"))
        return result

    for section, is_dev in _SECTIONS:
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, list):
            result.unsupported.append(_unsupported(section, "section is not a list"))
            continue
        for entry in block:
            if len(result.dependencies) >= MAX_DEPENDENCIES:
                result.unsupported.append(_unsupported(
                    "", "dependency limit reached; remaining entries ignored"))
                return result
            if not isinstance(entry, dict):
                result.unsupported.append(_unsupported(section, "malformed entry"))
                continue
            name, version = entry.get("name"), entry.get("version")
            label = f"{name}: {version}"
            if (not isinstance(name, str) or len(name) > MAX_NAME_LENGTH
                    or not _NAME_RE.fullmatch(name.lower())):
                result.unsupported.append(_unsupported(label, "invalid package name"))
                continue
            resolved = exact_composer_version(version)
            if resolved is None:
                result.unsupported.append(_unsupported(
                    label, "not an exact stable version (branch or prerelease)"))
                continue
            result.dependencies.append(Dependency(
                name=name.lower(),
                ecosystem=Ecosystem.PACKAGIST,
                version_spec=version,
                resolved_version=resolved,
                source_file=source_file,
                is_dev=is_dev,
            ))
    return result
