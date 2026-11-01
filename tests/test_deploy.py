import logging
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from dependency_compass import api
from dependency_compass.api import app_from_env, create_app
from dependency_compass.ratelimit import RateLimiter
from test_cli import services

ROOT = Path(__file__).parent.parent
TEXT = {"content-type": "text/plain"}


def requirement_lines(name):
    lines = (ROOT / name).read_text().splitlines()
    return [l for l in lines if l.strip() and not l.startswith("#")]


def test_runtime_requirements_are_exact_pins():
    lines = requirement_lines("requirements.txt")
    assert all(re.fullmatch(r"[A-Za-z0-9_.-]+==[\w.]+", l) for l in lines), lines
    names = {l.split("==")[0].lower() for l in lines}
    assert {"fastapi", "uvicorn", "httpx", "packaging", "starlette"} <= names
    assert "pytest" not in names                       # test tools stay out


def test_dev_requirements_include_runtime():
    assert requirement_lines("requirements-dev.txt")[0] == "-r requirements.txt"


def test_render_blueprint_uses_safe_start_command():
    text = (ROOT / "render.yaml").read_text()
    assert "--factory dependency_compass.api:app_from_env" in text
    assert "--no-proxy-headers" in text and "--port $PORT" in text
    assert "healthCheckPath: /healthz" in text
    assert "--workers" not in text                     # limiter is per process


@pytest.mark.parametrize("env, trust, docs", [
    ({}, False, False),
    ({"DC_TRUST_PROXY": "1", "DC_ENABLE_DOCS": "1"}, True, True),
    ({"DC_TRUST_PROXY": "true"}, False, False),       # only exactly "1"
])
def test_app_from_env(monkeypatch, env, trust, docs):
    for key in ("DC_TRUST_PROXY", "DC_ENABLE_DOCS", "DC_LOG_FORWARDED"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    seen = {}
    monkeypatch.setattr(api, "create_app", lambda **kw: seen.update(kw))
    app_from_env()
    assert (seen["trust_proxy"], seen["docs"]) == (trust, docs)


def forwarded_log(caplog, enabled):
    app = create_app(services(), RateLimiter(100, 100), log_forwarded=enabled)
    with caplog.at_level(logging.INFO, logger="dependency_compass.api"):
        TestClient(app).post("/api/scan", params={"filename": "requirements.txt"},
                             content="", headers={**TEXT,
                             "x-forwarded-for": "1.2.3.4\x1b[31m, 5.6.7.8"})
    return [r.getMessage() for r in caplog.records if "forwarded" in r.getMessage()]


def test_forwarded_header_not_logged_by_default(caplog):
    assert forwarded_log(caplog, False) == []


def test_forwarded_header_logged_sanitized_when_enabled(caplog):
    [line] = forwarded_log(caplog, True)
    assert "x-forwarded-for=1.2.3.4[31m, 5.6.7.8" in line and "\x1b" not in line
