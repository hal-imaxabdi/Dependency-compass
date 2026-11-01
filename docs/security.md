# Security design

The tool parses files from strangers and data from third-party feeds, so all
of it is treated as untrusted.

## Fail closed
- Any OSV error aborts the scan. There are no partial results that look complete.
- If the CISA KEV catalog is unreachable, the scan still runs, but every
  finding's exploitation status is *unknown* (never `false`), and the report
  says so. A stale copy (under 7 days old) is used if available, and labelled.
- The CLI exits with a dedicated code (3 or 4) when it couldn't check everything.

## Uploads
- **Never stored.** The API reads the raw request body into memory in chunks,
  capped at 1 MB. It is deliberately not multipart, because Starlette spools
  large multipart uploads to temporary files on disk.
- File type is checked by name before the body is read. Only the base name is
  used: client paths are never echoed.

## Limits on untrusted input
Body size, line length, number of dependencies, name and version length, JSON
nesting depth, advisories per scan, and KEV catalog size and entry count.

## Output
- Package names and advisory text are stripped of control characters, ANSI
  escapes and bidi overrides, then truncated, so a malicious lockfile can't
  rewrite your terminal.
- The web page builds the DOM with `textContent` only. A test fails if
  `innerHTML`, `eval` or similar ever appear.

## Web
- Strict Content Security Policy: same-origin scripts, styles, fonts and
  requests only, with no inline code. Fonts are self-hosted, and there are no
  CDNs or trackers.
- API responses send `default-src 'none'`, `no-store` and `nosniff`.
- Errors are fixed `{"error": "..."}` messages, with no stack traces or
  exception text. Details are logged server-side only.

## Rate limiting
- Per client (10 scans/min) and global (60/min), to protect OSV and KEV from
  abuse through this app.
- The client IP is read from `X-Forwarded-For` only at a **measured** proxy
  depth. On Render the chain is `client, Cloudflare, internal`, so the client
  is the 3rd entry from the right (`DC_PROXY_HOPS=3`), and spoofed entries
  added on the left are ignored. If the header looks wrong, all such requests
  share one bucket: stricter, never looser.

## Network
Explicit timeouts, retries only on transient errors (with backoff), and OSV
IDs checked against an allow-list before they're used in URLs.

## Supply chain
- Every dependency is pinned to an exact version.
- GitHub Actions are pinned to full commit SHAs (a test enforces it), skipping
  releases younger than two weeks.
- CI tokens are read-only, and Action inputs are passed through `env`, never
  pasted into shell scripts, to prevent command injection.
