from __future__ import annotations

import json
import re

from dependency_compass.models import (
    Dependency, Ecosystem, ParseResult, UnsupportedEntry,
)

MAX_SPEC_LENGTH = 256

# Exact semver only: optional "=" or "v", three numbers without leading
# zeros, optional prerelease. [0-9] (not \d) so Unicode digits never match.
_EXACT_RE = re.compile(
    r"=?v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?"
)


def exact_npm_version(spec: str) -> str | None:
    """Return a version only if the spec pins exactly one release."""
    spec = spec.strip()
    if len(spec) > MAX_SPEC_LENGTH:
        return None
    match = _EXACT_RE.fullmatch(spec)
    if match is None:
        return None
    major, minor, patch, pre = match.groups()
    return f"{major}.{minor}.{patch}{pre or ''}"


MAX_NAME_LENGTH = 214      # npm's own package-name limit
MAX_DEPENDENCIES = 5000

_SECTIONS = (
    ("dependencies", False),
    ("devDependencies", True),
    ("optionalDependencies", False),   # installed by default, so not dev
)


def _truncate(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _unsupported(content: str, reason: str) -> UnsupportedEntry:
    return UnsupportedEntry(None, _truncate(content), reason)


def _spec_problem(spec: str) -> str | None:
    """Return a reason if this spec cannot be matched by name + version."""
    s = spec.strip()
    for prefix in ("git+", "git:", "github:", "file:", "link:",
                   "workspace:", "http:", "https:"):
        if s.startswith(prefix):
            return "git/URL/local-path reference cannot be matched"
    if s.startswith("npm:"):
        return "npm alias installs a different package; cannot match by name"
    return None


def parse_package_json(text: str, source_file: str = "package.json") -> ParseResult:
    result = ParseResult()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        result.unsupported.append(_unsupported("", "invalid or too deeply nested JSON"))
        return result

    if not isinstance(data, dict):
        result.unsupported.append(_unsupported("", "top level of JSON is not an object"))
        return result

    for section, is_dev in _SECTIONS:
        block = data.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            result.unsupported.append(_unsupported(section, "section is not an object"))
            continue
        for name, spec in block.items():
            if len(result.dependencies) >= MAX_DEPENDENCIES:
                result.unsupported.append(_unsupported(
                    "", "dependency limit reached; remaining entries ignored"))
                return result
            label = f"{name}: {spec}"
            if not isinstance(spec, str) or len(name) > MAX_NAME_LENGTH or not name:
                result.unsupported.append(_unsupported(label, "invalid name or spec"))
                continue
            problem = _spec_problem(spec)
            if problem:
                result.unsupported.append(_unsupported(label, problem))
                continue
            result.dependencies.append(Dependency(
                name=name,
                ecosystem=Ecosystem.NPM,
                version_spec=spec,
                resolved_version=exact_npm_version(spec),
                source_file=source_file,
                is_dev=is_dev,
            ))

    if "peerDependencies" in data:
        result.unsupported.append(_unsupported(
            "peerDependencies", "peer dependencies are not analyzed"))

    return result
