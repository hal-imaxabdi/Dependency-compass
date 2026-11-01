# How ranking works

Findings are compared rule by rule. A later rule only breaks ties left by the
earlier ones, so every position can be explained. A package with several
advisories is ranked by its worst one.

| # | Rule | Why |
|---|---|---|
| 1 | **Actively exploited first:** any advisory listed in the [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Attackers are using it right now |
| 2 | **Severity:** critical > high > *unknown* > medium > low | Unknown is ranked above medium on purpose: missing data shouldn't make something look safer |
| 3 | **Production before dev** | Lockfiles say which. For requirements files it's guessed from the name (`requirements-dev.txt`, `test-requirements.txt`) and marked "assumed" |
| 4 | **Direct before transitive** | You can upgrade a direct dependency yourself |
| 5 | **Fix available:** all advisories fixed > some > none | Do what you can act on first |
| 6 | **Name, then version** | Same input, same order, every time |

Every package shows these reasons under **Details** (web) or **Why it ranks
here** (CLI).

## The upgrade target

For each package you get one version to upgrade to: the **smallest fixed
version newer than yours that falls outside every advisory's affected range**.

- Versions are compared with PEP 440 (PyPI) or SemVer (npm) rules.
- If any range can't be compared safely, no target is shown. A wrong "upgrade
  to X" is worse than none.
- Upgrades that cross a major version are marked **major**: check the
  changelog for breaking changes.
- Advisories with no fix at all can't be solved by upgrading, so the target
  says how many it covers ("fixes 3 of 4").

## "Not checked"

Anything the tool couldn't verify is listed under **Not checked**, never
counted as safe:

- version ranges (`>=2.0`, `^4.1.0`): the installed version is unknown
- lines it can't parse, `-r` includes, URLs and VCS references
- the CISA KEV catalog being unreachable (exploitation status becomes
  *unknown*, never "not exploited")
