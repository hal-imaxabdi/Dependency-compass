import json

import httpx
import pytest

from dependency_compass.models import Ecosystem
from dependency_compass.osv_client import OSVClient, OSVError, PackageQuery


def make_client(handler):
    return OSVClient(transport=httpx.MockTransport(handler))


def test_results_map_back_in_input_order():
    seen = {}

    def handler(request):
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "GHSA-1", "modified": "2023-01-01T00:00:00Z"}]},
            {},
        ]})

    queries = [
        PackageQuery("jinja2", Ecosystem.PYPI, "2.4.1"),
        PackageQuery("left-pad", Ecosystem.NPM, "1.3.0"),
    ]
    assert make_client(handler).query_batch(queries) == [["GHSA-1"], []]
    assert seen["path"] == "/v1/querybatch"
    assert seen["body"] == {"queries": [
        {"package": {"name": "jinja2", "ecosystem": "PyPI"}, "version": "2.4.1"},
        {"package": {"name": "left-pad", "ecosystem": "npm"}, "version": "1.3.0"},
    ]}


QUERIES = [
    PackageQuery("jinja2", Ecosystem.PYPI, "2.4.1"),
    PackageQuery("left-pad", Ecosystem.NPM, "1.3.0"),
]


def raising(exc_class):
    def handler(request):
        raise exc_class("boom", request=request)
    return handler


OUTAGES = {
    "http_500": lambda request: httpx.Response(500),
    "timeout": raising(httpx.ReadTimeout),
    "connect_error": raising(httpx.ConnectError),
    "not_json": lambda request: httpx.Response(200, content=b"<html>oops"),
    "missing_results": lambda request: httpx.Response(200, json={}),
    "length_mismatch": lambda request: httpx.Response(
        200, json={"results": [{}]}),
}


@pytest.mark.parametrize("handler", OUTAGES.values(), ids=OUTAGES.keys())
def test_outage_raises_osv_error_never_empty(handler):
    with pytest.raises(OSVError):
        make_client(handler).query_batch(QUERIES)


def big_queries(n=2500):
    return [PackageQuery("pkg", Ecosystem.NPM, str(i)) for i in range(n)]


def test_large_input_is_split_into_ordered_batches():
    sizes = []

    def handler(request):
        qs = json.loads(request.content)["queries"]
        sizes.append(len(qs))
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "ID-" + q["version"]}]} for q in qs]})

    result = make_client(handler).query_batch(big_queries())
    assert sizes == [1000, 1000, 500]
    assert result == [["ID-" + str(i)] for i in range(2500)]


def test_empty_input_makes_no_request():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"results": []})

    assert make_client(handler).query_batch([]) == []
    assert calls == []


def test_failure_in_later_batch_raises_not_partial():
    calls = []

    def handler(request):
        calls.append(1)
        if len(calls) == 2:
            return httpx.Response(500)
        qs = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [{} for _ in qs]})

    with pytest.raises(OSVError):
        make_client(handler).query_batch(big_queries())
