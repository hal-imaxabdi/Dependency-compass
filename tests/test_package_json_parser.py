import pytest

from dependency_compass.models import Ecosystem
from dependency_compass.parsers.package_json import exact_npm_version, parse_package_json

EXACT = [
    ("1.2.3", "1.2.3"),
    ("=1.2.3", "1.2.3"),
    ("v1.2.3", "1.2.3"),
    ("  1.2.3  ", "1.2.3"),
    ("1.2.3-beta.1", "1.2.3-beta.1"),
]


@pytest.mark.parametrize("spec, expected", EXACT)
def test_exact_pins_resolve(spec, expected):
    assert exact_npm_version(spec) == expected


NOT_EXACT = [
    "^1.2.3", "~1.2.3", ">=1.2.3", "*", "latest", "next",
    "1.2.x", "1.2", "1", "", "1.2.3 - 2.0.0", "1.2.3 || 2.0.0",
    "01.2.3", "1.2.3+build5", "git+https://example.com/a.git",
    "file:../lib", "npm:other@1.0.0",
]


@pytest.mark.parametrize("spec", NOT_EXACT)
def test_non_exact_specs_do_not_resolve(spec):
    assert exact_npm_version(spec) is None


def test_sections_and_dev_flag():
    text = '{"dependencies": {"a": "1.2.3", "b": "^2.0.0"}, "devDependencies": {"c": "3.0.0"}}'
    result = parse_package_json(text)
    by_name = {d.name: d for d in result.dependencies}
    assert by_name["a"].resolved_version == "1.2.3"
    assert by_name["a"].is_dev is False
    assert by_name["b"].resolved_version is None
    assert by_name["b"].version_spec == "^2.0.0"
    assert by_name["c"].is_dev is True
    assert by_name["c"].ecosystem == Ecosystem.NPM
    assert result.unsupported == []


def test_invalid_json_is_reported_not_swallowed():
    result = parse_package_json("{not json")
    assert result.dependencies == []
    assert len(result.unsupported) == 1
    assert result.unsupported[0].line_number is None
    assert "JSON" in result.unsupported[0].reason


def test_unsupported_specs_are_reported_not_dropped():
    text = (
        '{"dependencies": {"g": "git+https://example.com/g.git", '
        '"f": "file:../lib", "alias": "npm:other@1.0.0", "ok": "1.0.0"}}'
    )
    result = parse_package_json(text)
    assert [d.name for d in result.dependencies] == ["ok"]
    assert len(result.unsupported) == 3
    reasons = " ".join(u.reason for u in result.unsupported)
    assert "alias" in reasons


def test_non_string_spec_is_reported():
    result = parse_package_json('{"dependencies": {"a": 123}}')
    assert result.dependencies == []
    assert len(result.unsupported) == 1


def test_deeply_nested_json_does_not_crash():
    result = parse_package_json("[" * 100000)
    assert result.dependencies == []
    assert len(result.unsupported) == 1


def test_top_level_must_be_object():
    result = parse_package_json("[1, 2, 3]")
    assert result.dependencies == []
    assert "not an object" in result.unsupported[0].reason


def test_peer_dependencies_are_reported():
    result = parse_package_json('{"peerDependencies": {"react": "^18"}}')
    assert result.dependencies == []
    assert any("peer" in u.reason for u in result.unsupported)
