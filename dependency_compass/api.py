"""HTTP API: POST /api/scan?filename=NAME with the file content as the body.

Security decisions:
- The body is raw text (Content-Type: text/plain), read in chunks and capped
  at MAX_BODY_BYTES. Not multipart: Starlette spools large multipart uploads
  to a temp file on disk, and uploads must never be stored.
- File type is checked by name before the body is read (same rules as CLI).
- Rate limited per client IP and globally (see ratelimit.py). Behind
  proxies set DC_PROXY_HOPS=N: the client is the Nth X-Forwarded-For entry
  from the right. Each proxy appends the address it received from, so the
  rightmost N entries are written by proxies we trust; anything further left
  is client-controlled. Measured on Render (Cloudflare -> load balancer ->
  internal proxy): "<spoofed>, <client>, <cloudflare>, <internal>" -> N=3.
  Missing or invalid entry -> fall back to the peer address (shared bucket:
  stricter, never looser).
- Every error is {"error": "..."} with a fixed message: no stack traces,
  exception text or echoed input. Unexpected errors are logged server-side.
- OSV failures return 503 and no results (fail closed).
- DC_LOG_FORWARDED=1 (temporary, off by default) logs the raw
  X-Forwarded-For header, sanitized, to check what the proxy really sends.
- The page (/ and /static) gets its own CSP: only same-origin scripts,
  styles and fetches, no inline code. API responses get default-src 'none'.

Run: uvicorn --factory dependency_compass.api:app_from_env
"""
from __future__ import annotations

import ipaddress
import logging
import math
import os
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from dependency_compass.cli import Services, default_services
from dependency_compass.osv_client import OSVError
from dependency_compass.ratelimit import RateLimiter
from dependency_compass.report import clean_text, to_dict
from dependency_compass.scanner import (
    UnsupportedFileError, check_filename, parse_file, scan,
)
from dependency_compass.triage import rank_findings

log = logging.getLogger(__name__)

MAX_BODY_BYTES = 1024 * 1024
PER_CLIENT_LIMIT = 10   # scans per minute per IP
GLOBAL_LIMIT = 60       # scans per minute in total
MAX_CLIENT_ID = 64
MAX_PROXY_HOPS = 10
STATIC_DIR = Path(__file__).parent / "static"
API_CSP = "default-src 'none'; frame-ancestors 'none'"
PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; img-src 'self'; font-src 'self'; "
            "form-action 'none'; base-uri 'none'; frame-ancestors 'none'")
FONT_CACHE = "public, max-age=604800, immutable"   # fonts never change in place
SECURITY_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy": API_CSP,
}


class ApiError(Exception):
    def __init__(self, status: int, message: str,
                 headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status, self.message, self.headers = status, message, headers


def _error(status: int, message: str,
           headers: dict[str, str] | None = None) -> JSONResponse:
    return JSONResponse({"error": message}, status_code=status,
                        headers={**SECURITY_HEADERS, **(headers or {})})


def client_id(request: Request, proxy_hops: int) -> str:
    peer = request.client.host if request.client else "unknown"
    if proxy_hops <= 0:
        return peer
    entries = request.headers.get("x-forwarded-for", "").split(",")
    if len(entries) < proxy_hops:
        return peer
    candidate = entries[-proxy_hops].strip()[:MAX_CLIENT_ID]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return peer


def proxy_hops_from_env(value: str | None) -> int:
    """0..MAX_PROXY_HOPS; anything else means "don't trust the header"."""
    if value is None or not value.isdigit():
        return 0
    hops = int(value)
    return hops if hops <= MAX_PROXY_HOPS else 0


def _check_content_type(request: Request) -> None:
    media = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media != "text/plain":
        raise ApiError(415, "send the file content as text/plain")


async def read_body(request: Request) -> str:
    """Read at most MAX_BODY_BYTES into memory; never touches disk."""
    length = request.headers.get("content-length")
    if length is not None:
        if not length.isdigit():
            raise ApiError(400, "invalid Content-Length")
        if int(length) > MAX_BODY_BYTES:
            raise ApiError(413, "file is larger than 1 MB")
    body = bytearray()
    async for chunk in request.stream():
        body += chunk
        if len(body) > MAX_BODY_BYTES:
            raise ApiError(413, "file is larger than 1 MB")
    try:
        return body.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ApiError(400, "file is not valid UTF-8") from None


def _run_scan(services: Services, filename: str, text: str) -> dict:
    name, parsed = parse_file(filename, text)
    result = scan(parsed, name, services.osv, services.cache, services.kev)
    return to_dict(result, rank_findings(result.findings), name)


def create_app(services: Services | None = None,
               limiter: RateLimiter | None = None,
               proxy_hops: int = 0, docs: bool = False,
               log_forwarded: bool = False) -> FastAPI:
    services = services or default_services()
    limiter = limiter or RateLimiter(PER_CLIENT_LIMIT, GLOBAL_LIMIT)
    app = FastAPI(title="Dependency Compass",
                  docs_url="/docs" if docs else None, redoc_url=None,
                  openapi_url="/openapi.json" if docs else None)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        page = path == "/" or path.startswith("/static/")
        for key, value in SECURITY_HEADERS.items():
            response.headers.setdefault(key, value)
        if page and response.status_code == 200:
            response.headers["Content-Security-Policy"] = PAGE_CSP
            if path.startswith("/static/fonts/"):
                response.headers["Cache-Control"] = FONT_CACHE
        return response

    @app.exception_handler(ApiError)
    async def api_error(request: Request, exc: ApiError) -> JSONResponse:
        return _error(exc.status, exc.message, exc.headers)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        message = "not found" if exc.status_code == 404 else "request not allowed"
        return _error(exc.status_code, message)

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        return _error(400, "invalid request")

    @app.exception_handler(Exception)
    async def unexpected(request: Request, exc: Exception) -> JSONResponse:
        log.exception("unhandled error")
        return _error(500, "internal error")

    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/healthz")
    async def healthz() -> dict:
        return {"status": "ok"}

    @app.post("/api/scan")
    async def scan_endpoint(request: Request) -> JSONResponse:
        if log_forwarded:
            log.info("peer=%s x-forwarded-for=%s",
                     request.client.host if request.client else "unknown",
                     clean_text(request.headers.get("x-forwarded-for", "")))
        wait = limiter.check(client_id(request, proxy_hops))
        if wait is not None:
            raise ApiError(429, "too many scans; try again shortly",
                           {"Retry-After": str(max(1, math.ceil(wait)))})
        try:
            filename = check_filename(request.query_params.get("filename", ""))
        except UnsupportedFileError as exc:
            raise ApiError(400, str(exc)) from None
        _check_content_type(request)
        text = await read_body(request)
        try:
            data = await run_in_threadpool(_run_scan, services, filename, text)
        except OSVError:
            raise ApiError(503, "vulnerability database unavailable; "
                                "no results reported (fail closed)") from None
        except Exception:
            log.exception("scan failed")
            raise ApiError(500, "internal error") from None
        return JSONResponse(data)

    return app


def app_from_env() -> FastAPI:
    logging.basicConfig(level=logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)   # one line per GET
    return create_app(proxy_hops=proxy_hops_from_env(os.environ.get("DC_PROXY_HOPS")),
                      docs=os.environ.get("DC_ENABLE_DOCS") == "1",
                      log_forwarded=os.environ.get("DC_LOG_FORWARDED") == "1")
