import json

import httpx

from dependency_compass.models import Ecosystem
from dependency_compass.osv_client import OSVClient, PackageQuery


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
