from __future__ import annotations
import re

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from dependency_compass.models import (
    Dependency, Ecosystem, ParseResult, UnsupportedEntry,
)

MAX_LINE_LENGTH = 2000
MAX_DEPENDENCIES = 5000
_COMMENT_RE = re.compile(r"(^|\s)#.*$")
_HASH_RE = re.compile(r"\s--hash=\S+")


def _truncate(text: str, limit: int = 200) -> str:
    return text if len(text) <= limit else text[:limit] + "…"


def _logical_lines(text: str):
    """Yield (starting_line_number, joined_line), honoring trailing-backslash continuations."""
    buffer: list[str] = []
    start: int | None = None
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        if start is None:
            start = number
        if line.endswith("\\"):
            buffer.append(line[:-1])
            continue
        buffer.append(line)
        yield start, " ".join(buffer)
        buffer, start = [], None
    if buffer:
        yield start, " ".join(buffer)


def _exact_version(req: Requirement) -> str | None:
    """Return a version only if the specifier pins exactly one concrete release."""
    specs = list(req.specifier)
    if len(specs) == 1 and specs[0].operator in ("==", "==="):
        version = specs[0].version
        if not version.endswith(".*"):
            return version
    return None


def parse_requirements(text: str, source_file: str = "requirements.txt") -> ParseResult:
    result = ParseResult()

    for line_no, line in _logical_lines(text):
        if len(line) > MAX_LINE_LENGTH:
            result.unsupported.append(
                UnsupportedEntry(line_no, _truncate(line), "line too long"))
            continue

        line = _HASH_RE.sub("", _COMMENT_RE.sub("", line)).strip()
        if not line:
            continue

        if line.startswith("-"):
            result.unsupported.append(UnsupportedEntry(
                line_no, _truncate(line), "pip option or include not supported"))
            continue

        try:
            req = Requirement(line)
        except InvalidRequirement:
            result.unsupported.append(UnsupportedEntry(
                line_no, _truncate(line), "could not parse requirement"))
            continue

        if req.url:
            result.unsupported.append(UnsupportedEntry(
                line_no, _truncate(line), "direct URL/VCS reference cannot be matched"))
            continue

        if len(result.dependencies) >= MAX_DEPENDENCIES:
            result.unsupported.append(UnsupportedEntry(
                line_no, "", "dependency limit reached; remaining lines ignored"))
            break

        result.dependencies.append(Dependency(
            name=canonicalize_name(req.name),
            ecosystem=Ecosystem.PYPI,
            version_spec=str(req.specifier),
            resolved_version=_exact_version(req),
            source_file=source_file,
        ))

    return result
