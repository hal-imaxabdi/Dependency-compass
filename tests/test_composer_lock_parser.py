import json

from dependency_compass.models import Ecosystem
from dependency_compass.parsers.composer_lock import (
    exact_composer_version, parse_composer_lock,
)
from dependency_compass.versions import version_key

LOCK = json.dumps({
    "packages": [
        {"name": "symfony/http-kernel", "version": "v5.4.21"},
        {"name": "Monolog/Monolog", "version": "2.9.1"},
        {"name": "acme/branch", "version": "dev-main"},
        {"name": "acme/beta", "version": "2.0.0-beta1"},
        {"name": "../evil", "version": "1.0.0"},
        "not an object",
    ],
    "packages-dev": [
        {"name": "phpunit/phpunit", "version": "9.6.13"},
    ],
})


def test_parses_exact_versions_and_dev_flag():
    result = parse_composer_lock(LOCK)
    by_name = {d.name: d for d in result.dependencies}
    assert set(by_name) == {"symfony/http-kernel", "monolog/monolog", "phpunit/phpunit"}
    assert by_name["symfony/http-kernel"].resolved_version == "5.4.21"
    assert by_name["phpunit/phpunit"].is_dev is True
    assert by_name["monolog/monolog"].is_dev is False
    assert all(d.ecosystem == Ecosystem.PACKAGIST for d in result.dependencies)


def test_branches_prereleases_and_bad_entries_are_blind_spots():
    result = parse_composer_lock(LOCK)
    assert len(result.unsupported) == 4


def test_invalid_json_is_reported_not_raised():
    result = parse_composer_lock("{not json")
    assert result.dependencies == [] and len(result.unsupported) == 1


def test_deeply_nested_json_is_reported_not_raised():
    result = parse_composer_lock("[" * 100_000 + "]" * 100_000)
    assert result.dependencies == [] and len(result.unsupported) == 1


def test_unknown_layout_is_reported():
    result = parse_composer_lock('{"something": "else"}')
    assert result.dependencies == [] and len(result.unsupported) == 1


def test_wrong_section_type_is_reported():
    result = parse_composer_lock('{"packages": [], "packages-dev": {"a": 1}}')
    assert result.dependencies == [] and len(result.unsupported) == 1


def test_exact_version_accepts_only_stable_releases():
    assert exact_composer_version("v1.2.3") == "1.2.3"
    assert exact_composer_version("1.2.3") == "1.2.3"
    for bad in ("1.2", "1.2.3-RC1", "dev-main", "1.2.3.4", "01.2.3", None, "1" * 200):
        assert exact_composer_version(bad) is None


def test_packagist_versions_compare_stable_only():
    eco = Ecosystem.PACKAGIST
    assert version_key("5.4.9", eco) < version_key("5.4.21", eco)
    assert version_key("1.0.0-beta1", eco) is None
