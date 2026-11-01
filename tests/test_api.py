import pytest
from fastapi.testclient import TestClient

from dependency_compass import api
from dependency_compass.api import create_app
from dependency_compass.kev import KEVStatus
from dependency_compass.ratelimit import RateLimiter
from test_cli import rec, services

TEXT = {"content-type": "text/plain; charset=utf-8"}


def client(svc=None, limiter=None, proxy_hops=0, raise_errors=True):
    app = create_app(svc or services(), limiter or RateLimiter(1000, 1000),
                     proxy_hops=proxy_hops)
    return TestClient(app, raise_server_exceptions=raise_errors)


def post(c, body="flask==2.0.0\n", filename="requirements.txt", headers=TEXT):
    return c.post("/api/scan", params={"filename": filename},
                  content=body, headers=headers)


def test_scan_returns_report_json():
    svc = services({"jinja2": [rec("PYSEC-1", "jinja2", aliases=["CVE-2024-0001"])]})
    r = post(client(svc), "jinja2==2.4.1\nflask==2.0.0\n")
    assert r.status_code == 200
    data = r.json()
    assert data["schema_version"] == 1 and data["file"] == "requirements.txt"
    assert data["findings"][0]["package"] == "jinja2"
    assert data["findings"][0]["in_kev"] is True
    assert data["summary"]["clean"] == 1


def test_path_in_filename_is_stripped():
    r = post(client(), filename="../../home/user/requirements.txt")
    assert r.status_code == 200 and r.json()["file"] == "requirements.txt"
    assert "home" not in r.text


def test_security_headers_on_success_and_error():
    c = client()
    for r in (post(c), post(c, filename="setup.py"), c.get("/nope")):
        assert r.headers["cache-control"] == "no-store"
        assert r.headers["x-content-type-options"] == "nosniff"
        assert "default-src 'none'" in r.headers["content-security-policy"]


def test_healthz():
    assert client().get("/healthz").json() == {"status": "ok"}


def test_docs_disabled_by_default():
    c = client()
    assert c.get("/docs").status_code == 404
    assert c.get("/openapi.json").status_code == 404


# --- errors ------------------------------------------------------------------

@pytest.mark.parametrize("filename", ["setup.py", "", "x" * 300])
def test_400_unsupported_file(filename):
    r = post(client(), filename=filename)
    assert r.status_code == 400 and set(r.json()) == {"error"}


def test_400_missing_filename():
    r = client().post("/api/scan", content="x", headers=TEXT)
    assert r.status_code == 400


def test_400_not_utf8():
    r = post(client(), body=b"\xff\xfe\x00")
    assert r.status_code == 400 and r.json() == {"error": "file is not valid UTF-8"}


def test_415_wrong_content_type():
    r = post(client(), headers={"content-type": "multipart/form-data; boundary=x"})
    assert r.status_code == 415


def test_413_by_content_length(monkeypatch):
    monkeypatch.setattr(api, "MAX_BODY_BYTES", 10)
    r = post(client(), body="flask==2.0.0\n" * 5)
    assert r.status_code == 413


def test_413_when_streamed_body_exceeds_limit(monkeypatch):
    monkeypatch.setattr(api, "MAX_BODY_BYTES", 10)

    def chunks():   # no Content-Length: chunked transfer
        yield b"flask==2.0.0\n"
        yield b"flask==2.0.0\n"
    r = post(client(), body=chunks())
    assert r.status_code == 413


def test_429_with_retry_after():
    c = client(limiter=RateLimiter(per_client=1, global_limit=100))
    assert post(c).status_code == 200
    r = post(c)
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1


# The header shape measured on Render: spoofed, client, Cloudflare, internal.
RENDER_XFF = "{spoof}103.184.179.164, 104.23.160.57, 10.28.37.5"


def xff(value):
    return {**TEXT, "x-forwarded-for": value}


def test_rate_limit_uses_nth_entry_from_right():
    c = client(limiter=RateLimiter(per_client=1, global_limit=100), proxy_hops=3)
    assert post(c, headers=xff(RENDER_XFF.format(spoof=""))).status_code == 200
    # Spoofed entries on the left don't give a fresh quota.
    for spoof in ("6.6.6.6, ", "7.7.7.7, 8.8.8.8, "):
        r = post(c, headers=xff(RENDER_XFF.format(spoof=spoof)))
        assert r.status_code == 429
    other = "203.0.113.9, 104.23.160.57, 10.28.37.5"
    assert post(c, headers=xff(other)).status_code == 200


@pytest.mark.parametrize("header", [
    "104.23.160.57, 10.28.37.5",          # too few entries
    "not-an-ip, 104.23.160.57, 10.28.37.5",
    "",
])
def test_bad_forwarded_header_falls_back_to_shared_peer_bucket(header):
    c = client(limiter=RateLimiter(per_client=1, global_limit=100), proxy_hops=3)
    assert post(c, headers=xff(header)).status_code == 200
    assert post(c, headers=xff("198.51.100.1, 104.23.160.57, 10.28.37.5")).status_code == 200
    assert post(c, headers=xff(header)).status_code == 429   # same peer bucket


@pytest.mark.parametrize("value, hops", [
    (None, 0), ("3", 3), ("0", 0), ("-1", 0), ("abc", 0), ("99", 0),
])
def test_proxy_hops_from_env(value, hops):
    assert api.proxy_hops_from_env(value) == hops


def test_forwarded_header_ignored_when_not_trusted():
    c = client(limiter=RateLimiter(per_client=1, global_limit=100))
    assert post(c, headers={**TEXT, "x-forwarded-for": "1.1.1.1"}).status_code == 200
    assert post(c, headers={**TEXT, "x-forwarded-for": "2.2.2.2"}).status_code == 429


def test_503_when_osv_down_fails_closed():
    r = post(client(services(down=True)))
    assert r.status_code == 503
    assert "fail closed" in r.json()["error"] and "findings" not in r.text


def test_kev_unavailable_is_reported_not_hidden():
    svc = services({"jinja2": [rec("PYSEC-1", "jinja2")]},
                   kev_status=KEVStatus.UNAVAILABLE)
    data = post(client(svc), "jinja2==2.4.1\n").json()
    assert data["summary"]["kev_status"] == "unavailable"
    assert data["findings"][0]["in_kev"] is None


def test_500_hides_internals(monkeypatch):
    def boom(*a):
        raise RuntimeError("secret /etc/passwd detail")
    monkeypatch.setattr(api, "_run_scan", boom)
    r = post(client(raise_errors=False))
    assert r.status_code == 500 and r.json() == {"error": "internal error"}
    assert "secret" not in r.text and "Traceback" not in r.text


def test_404_and_405_are_generic():
    c = client()
    assert c.get("/nope").json() == {"error": "not found"}
    r = c.get("/api/scan")
    assert r.status_code == 405 and r.json() == {"error": "request not allowed"}
