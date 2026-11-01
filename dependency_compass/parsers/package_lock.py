from __future__ import annotations

import json

from dependency_compass.models import (
    Dependency, Ecosystem, ParseResult, UnsupportedEntry,
)
from dependency_compass.parsers.package_json import (
    MAX_DEPENDENCIES, MAX_NAME_LENGTH, exact_npm_version,
)

_NM = "node_modules/"


def _truncate(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _unsupported(content: str, reason: str) -> UnsupportedEntry:
    return UnsupportedEntry(None, _truncate(content), reason)


def _name_from_path(path: str) -> str | None:
    """'node_modules/a/node_modules/@s/b' -> '@s/b'."""
    idx = path.rfind(_NM)
    if idx == -1:
        return None
    return path[idx + len(_NM):] or None


def _parse_packages(packages: dict, result: ParseResult, source_file: str) -> None:
    for path, entry in packages.items():
        if path == "":
            continue   # the root project itself, not a dependency
        if len(result.dependencies) >= MAX_DEPENDENCIES:
            result.unsupported.append(_unsupported(
                "", "dependency limit reached; remaining entries ignored"))
            return
        if not isinstance(path, str) or not isinstance(entry, dict):
            result.unsupported.append(_unsupported(str(path), "malformed entry"))
            continue
        name = entry.get("name") if isinstance(entry.get("name"), str) else None
        name = name or _name_from_path(path)
        if not name or len(name) > MAX_NAME_LENGTH:
            result.unsupported.append(_unsupported(path, "could not determine package name"))
            continue
        if entry.get("link") is True:
            result.unsupported.append(_unsupported(path, "workspace link has no version"))
            continue
        version = entry.get("version")
        resolved = exact_npm_version(version) if isinstance(version, str) else None
        if resolved is None:
            result.unsupported.append(_unsupported(
                f"{name}: {version}", "lockfile version is not an exact semver"))
            continue
        result.dependencies.append(Dependency(
            name=name,
            ecosystem=Ecosystem.NPM,
            version_spec=resolved,
            resolved_version=resolved,
            source_file=source_file,
            is_direct=path.count(_NM) == 1,
            is_dev=entry.get("dev") is True,
        ))


MAX_DEPTH = 50   # guards our own recursion on untrusted nesting


def _parse_v1(deps: dict, result: ParseResult, source_file: str,
              depth: int = 0, direct: bool = True) -> None:
    if depth > MAX_DEPTH:
        result.unsupported.append(_unsupported("", "dependency tree nested too deeply"))
        return
    for name, entry in deps.items():
        if len(result.dependencies) >= MAX_DEPENDENCIES:
            result.unsupported.append(_unsupported(
                "", "dependency limit reached; remaining entries ignored"))
            return
        if not isinstance(entry, dict) or len(name) > MAX_NAME_LENGTH or not name:
            result.unsupported.append(_unsupported(str(name), "malformed entry"))
            continue
        version = entry.get("version")
        resolved = exact_npm_version(version) if isinstance(version, str) else None
        if resolved is None:
            result.unsupported.append(_unsupported(
                f"{name}: {version}", "lockfile version is not an exact semver"))
        else:
            result.dependencies.append(Dependency(
                name=name,
                ecosystem=Ecosystem.NPM,
                version_spec=resolved,
                resolved_version=resolved,
                source_file=source_file,
                is_direct=direct,
                is_dev=entry.get("dev") is True,
            ))
        nested = entry.get("dependencies")
        if isinstance(nested, dict):
            _parse_v1(nested, result, source_file, depth + 1, direct=False)


def parse_package_lock(text: str, source_file: str = "package-lock.json") -> ParseResult:
    result = ParseResult()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, RecursionError):
        result.unsupported.append(_unsupported("", "invalid or too deeply nested JSON"))
        return result

    if not isinstance(data, dict):
        result.unsupported.append(_unsupported("", "top level of JSON is not an object"))
        return result

    packages = data.get("packages")
    legacy = data.get("dependencies")
    if isinstance(packages, dict):
        _parse_packages(packages, result, source_file)
    elif isinstance(legacy, dict):
        _parse_v1(legacy, result, source_file)
    else:
        result.unsupported.append(_unsupported(
            "", "unrecognized lockfile layout; nothing was analyzed"))
    return result
