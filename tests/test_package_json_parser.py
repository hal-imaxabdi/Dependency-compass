import pytest

from dependency_compass.parsers.package_json import exact_npm_version

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
