import json

import httpx
import pytest

from dependency_compass.models import Ecosystem
from dependency_compass.osv_client import OSVClient, OSVError, PackageQuery


def make_client(handler):
    return OSVClient(transport=httpx.MockTransport(handler),
                     sleep=lambda s: None)


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
        if len(calls) >= 2:
            return httpx.Response(500)
        qs = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [{} for _ in qs]})

    with pytest.raises(OSVError):
        make_client(handler).query_batch(big_queries())


def test_pagination_requeries_only_paginated_queries_and_merges():
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content)["queries"])
        if len(bodies) == 1:
            return httpx.Response(200, json={"results": [
                {"vulns": [{"id": "A"}], "next_page_token": "t0"},
                {},
                {"vulns": [{"id": "C"}]},
            ]})
        return httpx.Response(200, json={"results": [{"vulns": [{"id": "B"}]}]})

    queries = [PackageQuery(f"p{i}", Ecosystem.NPM, "1.0.0") for i in range(3)]
    assert make_client(handler).query_batch(queries) == [["A", "B"], [], ["C"]]
    assert len(bodies) == 2
    assert bodies[1] == [{"package": {"name": "p0", "ecosystem": "npm"},
                          "version": "1.0.0", "page_token": "t0"}]


def test_endless_pagination_raises_instead_of_truncating():
    calls = []

    def handler(request):
        calls.append(1)
        qs = json.loads(request.content)["queries"]
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "X"}], "next_page_token": "t"} for _ in qs]})

    with pytest.raises(OSVError):
        make_client(handler).query_batch(QUERIES[:1])
    assert len(calls) <= 20


def test_non_string_page_token_raises():
    def handler(request):
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "X"}], "next_page_token": 123}, {}]})

    with pytest.raises(OSVError):
        make_client(handler).query_batch(QUERIES)


def retry_client(handler, delays):
    return OSVClient(transport=httpx.MockTransport(handler),
                     sleep=delays.append)


def test_retries_503_then_succeeds_with_exponential_delays():
    delays, calls = [], []

    def handler(request):
        calls.append(1)
        if len(calls) < 3:
            return httpx.Response(503)
        return httpx.Response(200, json={"results": [{}]})

    assert retry_client(handler, delays).query_batch(QUERIES[:1]) == [[]]
    assert len(calls) == 3
    assert delays == [0.5, 1.0]


def test_retries_timeout_then_succeeds():
    delays, calls = [], []

    def handler(request):
        calls.append(1)
        if len(calls) == 1:
            raise httpx.ReadTimeout("slow", request=request)
        return httpx.Response(200, json={"results": [{}]})

    assert retry_client(handler, delays).query_batch(QUERIES[:1]) == [[]]
    assert len(calls) == 2


def test_gives_up_after_max_attempts_with_osv_error():
    delays, calls = [], []

    def handler(request):
        calls.append(1)
        return httpx.Response(500)

    with pytest.raises(OSVError):
        retry_client(handler, delays).query_batch(QUERIES[:1])
    assert len(calls) == 4
    assert delays == [0.5, 1.0, 2.0]


@pytest.mark.parametrize("status", [400, 404])
def test_non_429_client_errors_are_not_retried(status):
    delays, calls = [], []

    def handler(request):
        calls.append(1)
        return httpx.Response(status)

    with pytest.raises(OSVError):
        retry_client(handler, delays).query_batch(QUERIES[:1])
    assert len(calls) == 1
    assert delays == []


def test_malformed_body_is_not_retried():
    delays, calls = [], []

    def handler(request):
        calls.append(1)
        return httpx.Response(200, content=b"<html>oops")

    with pytest.raises(OSVError):
        retry_client(handler, delays).query_batch(QUERIES[:1])
    assert len(calls) == 1
