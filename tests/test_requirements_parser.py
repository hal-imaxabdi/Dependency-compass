import pytest

from dependency_compass.parsers.requirements import (
    is_dev_requirements_name, parse_requirements,
)


def names(result):
    return [d.name for d in result.dependencies]


def test_exact_pin_is_resolved():
    r = parse_requirements("requests==2.19.0\n")
    assert r.dependencies[0].resolved_version == "2.19.0"


def test_range_is_never_resolved():
    r = parse_requirements("django>=2.0\nflask~=2.0\nnumpy<2\n")
    assert all(d.resolved_version is None for d in r.dependencies)


def test_wildcard_pin_is_not_resolved():
    r = parse_requirements("django==3.2.*\n")
    assert r.dependencies[0].resolved_version is None


def test_name_normalization():
    r = parse_requirements("PyYAML==5.3\nZope_Interface==5.0\n")
    assert names(r) == ["pyyaml", "zope-interface"]


def test_extras_and_markers():
    r = parse_requirements('requests[security]==2.0.0 ; python_version < "3.9"\n')
    assert names(r) == ["requests"]
    assert r.dependencies[0].resolved_version == "2.0.0"


def test_comments_and_blank_lines():
    r = parse_requirements("# header\n\nflask==2.0.0  # web\n")
    assert names(r) == ["flask"]


def test_includes_and_options_are_reported_not_crashed():
    r = parse_requirements("-r other.txt\n-e .\n--index-url https://x\n")
    assert r.dependencies == []
    assert len(r.unsupported) == 3


def test_vcs_url_reported_unsupported():
    r = parse_requirements("pkg @ git+https://github.com/a/b.git\n")
    assert r.dependencies == []
    assert "URL" in r.unsupported[0].reason


def test_garbage_line_does_not_crash():
    r = parse_requirements("!!!not a requirement\nflask==2.0.0\n")
    assert names(r) == ["flask"]
    assert len(r.unsupported) == 1


def test_line_continuation_and_hashes():
    r = parse_requirements("flask==2.0.0 \\\n    --hash=sha256:abc\n")
    assert r.dependencies[0].resolved_version == "2.0.0"


def test_empty_input():
    r = parse_requirements("")
    assert r.dependencies == [] and r.unsupported == []
    

@pytest.mark.parametrize("name, is_dev", [
    ("requirements.txt", False),
    ("requirements-prod.txt", False),
    ("requirements-dev.txt", True),
    ("requirements_test.txt", True),
    ("dev-requirements.txt", True),
    ("test-requirements.txt", True),
    ("REQUIREMENTS-TESTING.txt", True),
    ("requirements-devops.txt", False),   # whole tokens only
])
def test_dev_inferred_from_file_name(name, is_dev):
    assert is_dev_requirements_name(name) is is_dev
    deps = parse_requirements("flask==2.0.0\n", name).dependencies
    assert deps[0].is_dev is is_dev
