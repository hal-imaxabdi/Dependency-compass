from __future__ import annotations

import re

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
