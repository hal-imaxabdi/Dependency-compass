<p align="center">
  <img src="dependency_compass/static/favicon.svg" width="72" alt="Dependency Compass logo">
</p>

<h1 align="center">Dependency Compass</h1>

<p align="center">
  <b>Find which vulnerable dependencies to fix first.</b><br>
  <a href="https://dependency-compass.onrender.com"><b>Try it in your browser</b></a> ·
  <a href="#github-action">GitHub Action</a> ·
  <a href="#command-line">CLI</a>
</p>

<p align="center">
  <a href="https://github.com/hal-imaxabdi/Dependency-compass/actions/workflows/ci.yml"><img src="https://github.com/hal-imaxabdi/Dependency-compass/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
</p>

Most scanners give you a long list of alerts. Dependency Compass gives you a
**ranked fix list** instead:

- **Most urgent first:** vulnerabilities attackers are exploiting right now
  ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog))
  come first, then by severity.
- **One upgrade per package:** the version that fixes everything, ready to copy.
- **Honest about gaps:** anything it couldn't check is listed as *Not checked*,
  never reported as safe.

![Ranked results for a sample requirements.txt](docs/screenshot.png)

## Web

Open **https://dependency-compass.onrender.com**, then drop in a
`package-lock.json` or `requirements.txt` (or click **Try a sample**).
Files are scanned in memory and never stored.

> It runs on a free server, so the first visit after a quiet period can take
> about 30 seconds to wake up.

## GitHub Action

Fail your build when a dependency has an actively exploited or high-severity
vulnerability:

```yaml
# .github/workflows/dependencies.yml
name: Dependencies
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: hal-imaxabdi/Dependency-compass@27f92da2bf5c8274e278ad114d976815f20ec256 # v0.1.0
        with:
          file: package-lock.json   # or requirements.txt
          fail-on: high             # critical | high | medium | low | any
```

| Input | Default | Meaning |
|---|---|---|
| `file` | required | Path to the file to scan |
| `fail-on` | `high` | Fail if any package is at or above this severity. Actively exploited ones always fail. |
| `strict` | `false` | `true` also fails when something couldn't be checked |

## Command line

```bash
pip install "git+https://github.com/hal-imaxabdi/Dependency-compass@v0.1.0"

dependency-compass scan package-lock.json
dependency-compass scan requirements.txt --json > report.json
```

```text
Dependency Compass: requirements.txt
6 vulnerable package(s) · 0 with no known advisories · 1 not checked

#1  django 3.2.0  [PyPI · prod · direct]
    → Upgrade to 5.2.17: fixes all 38 advisories (major version upgrade: check for breaking changes)
    - GHSA-2gwj-7jmv-h26r (critical)  SQL Injection in Django
      fixed in 2.2.28, 3.2.13, 4.0.4
    + 35 more (use --json for the full list)
```

**Exit codes**, for scripts and CI:

| Code | Meaning |
|---|---|
| `0` | Nothing at or above `--fail-on` |
| `1` | Found something to fix: actively exploited, or at/above `--fail-on` |
| `2` | Bad input: unreadable, too large, or unsupported file |
| `3` | Vulnerability database unreachable: no results at all |
| `4` | Incomplete: some things couldn't be checked (see `--strict`) |

## Supported files

| Ecosystem | File | Notes |
|---|---|---|
| npm | `package-lock.json` | **Best choice:** exact versions, including transitive dependencies |
| npm | `package.json` | Only lists ranges (`^4.1.0`), so most entries end up *Not checked* |
| Python | `requirements*.txt` | Only exact pins (`flask==2.0.0`) are checked |

## Limitations

- No support yet for Poetry, Pipenv, yarn or pnpm lockfiles.
- It doesn't know whether your code actually calls the vulnerable function.
- The upgrade target doesn't check for API changes beyond flagging major versions.

## More

- [How ranking works](docs/ranking.md): the six rules and how the upgrade target is chosen
- [Security design](docs/security.md): how untrusted files and feeds are handled
- [Development](docs/development.md): run it locally, architecture, configuration

Vulnerability data comes from [OSV.dev](https://osv.dev) and the
[CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog).
