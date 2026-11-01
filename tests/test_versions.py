import pytest

from dependency_compass.models import Ecosystem
from dependency_compass.versions import major, version_key

NPM, PYPI = Ecosystem.NPM, Ecosystem.PYPI


@pytest.mark.parametrize("ordered", [
    ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta",
     "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0"],   # SemVer spec example
    ["1.9.0", "1.10.0", "2.0.0", "10.0.0"],
])
def test_semver_precedence(ordered):
    keys = [version_key(v, NPM) for v in ordered]
    assert keys == sorted(keys)


def test_semver_ignores_build_metadata_and_v_prefix():
    assert version_key("v1.2.3+build.5", NPM) == version_key("1.2.3", NPM)


def test_pep440_ordering():
    keys = [version_key(v, PYPI) for v in ["2.0rc1", "2.0", "2.0.post1", "2.10"]]
    assert keys == sorted(keys)


@pytest.mark.parametrize("value, eco", [
    ("1.2", NPM), ("latest", NPM), ("1.2.3.4", NPM), ("not a version", PYPI),
    ("1" * 200, PYPI), (None, NPM),
])
def test_unparseable_is_none(value, eco):
    assert version_key(value, eco) is None


def test_major():
    assert major("4.17.21", NPM) == 4
    assert major("3.2.13", PYPI) == 3
    assert major("nope", NPM) is None
