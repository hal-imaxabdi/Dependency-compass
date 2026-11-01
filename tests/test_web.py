import re

from fastapi.testclient import TestClient

from dependency_compass.api import PAGE_CSP, STATIC_DIR, create_app
from dependency_compass.ratelimit import RateLimiter
from dependency_compass.scanner import parse_file
from test_cli import services


def client():
    return TestClient(create_app(services(), RateLimiter(1000, 1000)))


def test_index_served_with_page_csp():
    r = client().get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert r.headers["content-security-policy"] == PAGE_CSP
    assert '<script src="/static/app.js"' in r.text


def test_static_assets_served_with_page_csp():
    c = client()
    for path in ("/static/app.js", "/static/style.css",
                 "/static/sample-requirements.txt"):
        r = c.get(path)
        assert r.status_code == 200, path
        assert r.headers["content-security-policy"] == PAGE_CSP
        assert r.headers["x-content-type-options"] == "nosniff"


def test_missing_static_file_is_generic_404_with_strict_csp():
    r = client().get("/static/../api.py")
    assert r.status_code == 404
    assert "default-src 'none';" in r.headers["content-security-policy"]
    assert "script-src" not in r.headers["content-security-policy"]


def test_api_keeps_strict_csp():
    r = client().get("/healthz")
    assert "script-src" not in r.headers["content-security-policy"]


def test_page_has_no_inline_script_or_style():
    html = (STATIC_DIR / "index.html").read_text()
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "<style" not in html and " style=" not in html
    assert not re.search(r"\son[a-z]+=", html)   # no inline event handlers


def test_js_never_uses_unsafe_html_sinks():
    js = (STATIC_DIR / "app.js").read_text()
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML",
                 "document.write", "eval(", "new Function"):
        assert sink not in js.split("\n", 1)[1], sink   # skip header comment


def test_no_external_resources():
    html = (STATIC_DIR / "index.html").read_text()
    assert not re.search(r'(src|href)="https?://(?!osv\.dev|www\.cisa\.gov)', html)
    assert not re.search(r"(src|href)=\"https?://[^\"]*\.(js|css)", html)


def test_sample_parses_into_pins_and_a_blind_spot():
    text = (STATIC_DIR / "sample-requirements.txt").read_text()
    _, parsed = parse_file("requirements.txt", text)
    pinned = [d for d in parsed.dependencies if d.resolved_version]
    unpinned = [d for d in parsed.dependencies if not d.resolved_version]
    assert len(pinned) >= 5 and len(unpinned) == 1
