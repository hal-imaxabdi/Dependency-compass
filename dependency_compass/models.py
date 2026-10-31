from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum


class Ecosystem(str, Enum):
    PYPI = "PyPI"   # these strings must match OSV's ecosystem names exactly
    NPM = "npm"


@dataclass(frozen=True)
class Dependency:
    name: str
    ecosystem: Ecosystem
    version_spec: str                 # what the file said, e.g. ">=2.0,<3"
    resolved_version: str | None      # only set when we KNOW the exact version
    source_file: str
    is_direct: bool = True


@dataclass(frozen=True)
class UnsupportedEntry:
    line_number: int
    content: str                      # truncated; it is untrusted input
    reason: str


@dataclass
class ParseResult:
    dependencies: list[Dependency] = field(default_factory=list)
    unsupported: list[UnsupportedEntry] = field(default_factory=list)
    