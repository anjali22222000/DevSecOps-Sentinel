# Threat model

## Assets
CI runners and the secrets/network they can reach; the integrity of what gets installed; developers' trust in the gate.

## Attackers considered
| Attacker | Capability | Goal |
|---|---|---|
| Dependency-confusion publisher | Can publish any unclaimed name with any version on NPM/PyPI | Get a build to install their package instead of the internal one |
| Typosquatter | Can publish names close to popular packages | Be installed after a typo |
| Hostile repository content | Controls manifest/lockfile text scanned by Sentinel | Attack the scanner, its reports, the dashboard or the CI |

## What Sentinel does against each
| Threat | Mitigation | Residual risk |
|---|---|---|
| Public package shadows an internal name | V (higher public version) and S (public registration), CRITICAL floor; lockfile provenance check works offline | Needs correct `[internal]` config; cannot verify ownership |
| Unreserved internal name | MEDIUM finding (DC-002) | A 404 may mean "private in an owned scope" |
| Mis-configured resolution (`--extra-index-url`, `--trusted-host`, http index) | Rule-based configuration findings | Only `requirements.txt`/`Pipfile.lock` options are read |
| Typosquat of a well-known package | Edit-distance filters with false-positive controls | Seed list; short names skipped; real attackers may use other tricks |
| Scanner-input attacks: path/URL injection through package names | `fullmatch` validation before building URLs; invalid names are never requested | - |
| Scanner-output attacks: XSS via package names in reports | Jinja2 autoescape; dashboard inserts text only (tested with `<img onerror>` and `<script>` names) | - |
| Secret leakage via manifests | Credentials and query strings redacted at parse time | Secrets in free-text comments are not looked for |
| Registry outage or tampering turning into a "pass" | Failed lookups are `error` -> exit 2; partial evidence flagged; `block_on_incomplete` available | A convincing but false 200 response is trusted |
| Malicious redirects | Not followed | - |
| Oversized responses | 20 MB cap | - |
| CI abuse of the action | No `pull_request_target`; inputs reach shell via `env`, never inline; least-privilege permissions; scanner dependencies pinned | Action pinned by tag; no hash pinning yet |

## Explicit non-goals
Runtime/behavioural analysis of packages, vulnerability (CVE) scanning, automatic patching, ecosystems other than NPM and PyPI.
