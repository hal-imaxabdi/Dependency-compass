import pytest

from dependency_compass.advisory import parse_advisory
from dependency_compass.models import Ecosystem
from dependency_compass.osv_client import OSVError


def record(**over):
    base = {
        "id": "GHSA-p6mc-m468-83gw", "aliases": ["CVE-2020-8203"],
        "summary": "Prototype pollution", "modified": "2026-01-01T00:00:00.123456789Z",
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {"package": {"name": "lodash", "ecosystem": "npm"},
             "ranges": [{"type": "SEMVER", "events": [
                 {"introduced": "0"}, {"fixed": "4.17.19"}]}]},
            {"package": {"name": "lodash-es", "ecosystem": "npm"},
             "ranges": [{"type": "SEMVER", "events": [
                 {"introduced": "0"}, {"fixed": "4.17.20"}]}]},
            {"package": {"name": "lodash", "ecosystem": "RubyGems"},
             "ranges": [{"type": "ECOSYSTEM", "events": [
                 {"introduced": "0"}, {"fixed": "9.9.9"}]}]},
        ],
    }
    base.update(over)
    return base


def test_fix_comes_only_from_the_queried_package():
    adv = parse_advisory(record(), "lodash", Ecosystem.NPM)
    assert adv.fixed_versions == ("4.17.19",)
    assert adv.severity == "high"
    assert adv.aliases == ("CVE-2020-8203",)
    assert adv.modified == "2026-01-01T00:00:00.123456789Z"
    assert adv.withdrawn is False


def test_pypi_names_are_normalized():
    rec = record(affected=[{"package": {"name": "Jinja2", "ecosystem": "PyPI"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [
                                {"introduced": "0"}, {"fixed": "2.11.3"}]}]}])
    adv = parse_advisory(rec, "jinja2", Ecosystem.PYPI)
    assert adv.fixed_versions == ("2.11.3",)


def test_last_affected_only_means_no_fix_known():
    rec = record(affected=[{"package": {"name": "lodash", "ecosystem": "npm"},
                            "ranges": [{"type": "SEMVER", "events": [
                                {"introduced": "0"}, {"last_affected": "4.5.0"}]}]}])
    assert parse_advisory(rec, "lodash", Ecosystem.NPM).fixed_versions == ()


@pytest.mark.parametrize("label,expected", [
    ("MODERATE", "medium"), ("LOW", "low"), ("CRITICAL", "critical"),
    ("weird", "unknown"), (None, "unknown"), (5, "unknown"),
])
def test_severity_label_mapping(label, expected):
    rec = record(database_specific={"severity": label})
    assert parse_advisory(rec, "lodash", Ecosystem.NPM).severity == expected


def test_summary_is_truncated():
    adv = parse_advisory(record(summary="x" * 5000), "lodash", Ecosystem.NPM)
    assert len(adv.summary) <= 200


def test_withdrawn_is_flagged():
    adv = parse_advisory(record(withdrawn="2026-02-02T00:00:00Z"),
                         "lodash", Ecosystem.NPM)
    assert adv.withdrawn is True


@pytest.mark.parametrize("bad", [
    record(id=5), record(affected="nope"), record(affected=[]),
    record(affected=[{"package": {"name": "other", "ecosystem": "npm"}}]),
    record(modified=None),
])
def test_untrustworthy_records_raise(bad):
    with pytest.raises(OSVError):
        parse_advisory(bad, "lodash", Ecosystem.NPM)
