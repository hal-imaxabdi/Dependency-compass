"""Compare versions per ecosystem. Returns None when a version can't be parsed.

PyPI uses PEP 440 (packaging.version). npm uses SemVer 2.0 precedence:
release > its prereleases; numeric identifiers sort before alphanumeric.
"""
from __future__ import annotations

import re

from packaging.version import InvalidVersion, Version

from dependency_compass.models import Ecosystem

MAX_LENGTH = 128
_SEMVER_RE = re.compile(
    r"v?(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?")


def _semver_key(value: str) -> tuple | None:
    match = _SEMVER_RE.fullmatch(value)
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    if pre is None:
        pre_key: tuple = (1,)   # a release sorts after all its prereleases
    else:
        pre_key = (0, tuple((0, int(p), "") if p.isdigit() else (1, 0, p)
                            for p in pre.split(".")))
    return (int(major), int(minor), int(patch), pre_key)


def version_key(value: str, ecosystem: Ecosystem) -> object | None:
    """A sortable key, or None if we can't parse the version safely."""
    if not isinstance(value, str) or len(value) > MAX_LENGTH:
        return None
    if ecosystem is Ecosystem.PYPI:
        try:
            return Version(value)
        except InvalidVersion:
            return None
    if ecosystem is Ecosystem.PACKAGIST:
        # Composer orders prereleases differently from SemVer, so only
        # stable X.Y.Z is compared; anything else means "can't tell".
        key = _semver_key(value)
        return key if key is not None and key[3] == (1,) else None
    return _semver_key(value)


def major(value: str, ecosystem: Ecosystem) -> int | None:
    key = version_key(value, ecosystem)
    if key is None:
        return None
    return key.major if isinstance(key, Version) else key[0]
