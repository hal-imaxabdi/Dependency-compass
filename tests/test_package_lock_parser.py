from dependency_compass.models import Ecosystem
from dependency_compass.parsers.package_lock import parse_package_lock

V3 = (
    '{"lockfileVersion": 3, "packages": {'
    '"": {"name": "app", "version": "1.0.0"}, '
    '"node_modules/a": {"version": "1.2.3"}, '
    '"node_modules/a/node_modules/b": {"version": "2.0.0"}, '
    '"node_modules/c": {"version": "3.1.0", "dev": true}, '
    '"node_modules/@scope/d": {"version": "4.0.0"}, '
    '"node_modules/g": {"version": "git+https://example.com/g.git"}, '
    '"node_modules/w": {"link": true, "resolved": "../w"}'
    '}}'
)


def test_v3_resolves_exact_versions_and_flags():
    result = parse_package_lock(V3)
    by_name = {d.name: d for d in result.dependencies}
    assert set(by_name) == {"a", "b", "c", "@scope/d"}
    assert by_name["a"].resolved_version == "1.2.3"
    assert by_name["a"].is_direct is True
    assert by_name["b"].is_direct is False
    assert by_name["c"].is_dev is True
    assert by_name["@scope/d"].is_direct is True
    assert all(d.ecosystem == Ecosystem.NPM for d in result.dependencies)


def test_v3_reports_git_and_link_entries():
    result = parse_package_lock(V3)
    assert len(result.unsupported) == 2


V1 = (
    '{"lockfileVersion": 1, "dependencies": {'
    '"a": {"version": "1.2.3", "dependencies": {"b": {"version": "2.0.0"}}}, '
    '"c": {"version": "3.1.0", "dev": true}'
    '}}'
)


def test_v1_nested_tree():
    result = parse_package_lock(V1)
    by_name = {d.name: d for d in result.dependencies}
    assert set(by_name) == {"a", "b", "c"}
    assert by_name["a"].is_direct is True
    assert by_name["b"].is_direct is False
    assert by_name["b"].resolved_version == "2.0.0"
    assert by_name["c"].is_dev is True


def test_unknown_layout_is_reported_not_clean():
    result = parse_package_lock('{"lockfileVersion": 9}')
    assert result.dependencies == []
    assert len(result.unsupported) == 1


def test_invalid_and_deep_json_are_reported():
    for text in ("{oops", "[" * 100000, "[1]"):
        result = parse_package_lock(text)
        assert result.dependencies == []
        assert len(result.unsupported) == 1
