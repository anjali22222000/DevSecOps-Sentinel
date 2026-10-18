# Scoring model

## The original model (from the proposal)

```
R = min(100, Wv*V + Ws*S + Wt*T)        Wv + Ws + Wt = 1
V = 100 if public version > internal version, else 0
S = 100 if the scope is unclaimed publicly, else 0
T = (1 - d_L(a, b) / max(len(a), len(b))) * 100          (normalized Levenshtein similarity)
CRITICAL 80-100   HIGH 60-79.99   MEDIUM 30-59.99   SAFE 0-29.99
```

## What is implemented, and why it differs

Same formula, same weights (defaults Wv 0.4, Ws 0.3, Wt 0.3, validated to sum to 1) and same bands.
Four limitations of the original model forced small, documented adjustments.

| # | Limitation of the original | Adjustment |
|---|---|---|
| 1 | The formula cannot reach the proposal's own labels. With weights summing to 1, a higher public version alone gives V*Wv = 40 (MEDIUM, not CRITICAL), and T = 87.5% gives 26 (SAFE, not HIGH). | **Floors**: explicit minimum scores for specific evidence (below). `score = max(formula, highest applicable floor)`. Both numbers are shown in every finding. |
| 2 | Public metadata cannot say which version is "internal", nor who owns a name. | V compares against an **expected version** (config `expected_versions`, else the lockfile pin, else the manifest pin). If none is known, V is *unavailable*, not 0. S uses `owned_public` from config. |
| 3 | S as "scope unclaimed" cannot be read from a registry: a 404 also occurs for private packages in a scope you own. | S has defined states (below) and the 404 caveat is printed in the finding. |
| 4 | Levenshtein counts an adjacent swap as 2 edits, the most common typo-squat pattern. | `similarity.algorithm = "damerau"` by default (swap = 1 edit); `"levenshtein"` remains available. The reported T still uses the proposal's formula with the chosen distance. |

`min(100, ...)` is redundant when weights sum to 1 and indicators are at most 100; it is kept to match the proposal.

## Indicators

| Indicator | Applies to | Value |
|---|---|---|
| **V** version mismatch | names declared internal | 100 if the highest **public** version (all published versions, not just `latest`) is greater than the expected version by semver (NPM) or PEP 440 (PyPI); 0 otherwise; **unavailable** if no registry answer, no expected version, or versions cannot be compared |
| **S** namespace | internal names, and any name that is not registered publicly | internal & public & not reserved by you: **100**; no public package (cannot confirm reservation): **70**; reserved by you: **0**; not internal and exists publicly: 0; not internal and **not registered anywhere**: 70; unavailable if no evidence |
| **T** similarity | non-internal names | similarity % to the closest well-known name that passes the filters; 0 if none |

An unavailable indicator contributes 0 to the sum, is shown as "unavailable" in the breakdown, and
marks the finding **partial**. Partial findings are never described as verified.

## Floors

| Evidence | Floor | Rule |
|---|---|---|
| Internal name has a higher public version than expected | 80 (CRITICAL) | SENT-DC-001 |
| Internal package's lockfile entry was resolved from a public registry host | 80 (CRITICAL) | SENT-DC-001 |
| Lookalike with similarity >= 85% and the package is not established | 60 (HIGH) | SENT-TS-001 |
| Lookalike with lower similarity and not established | 30 (MEDIUM) | SENT-TS-001 |
| Name not registered publicly and (not declared internal, or not confirmed reserved) | 30 (MEDIUM) | SENT-DC-002 |

"Established" (to cut false positives) means at least 10 published versions, or first published at least
730 days ago when the registry provides dates (PyPI does; NPM abbreviated metadata does not).
Configuration findings are **rule-based**, not formula-based: extra index URL 40 (65 if internal PyPI
names are declared), trusted-host 35, plain-HTTP index 60.

## False-positive controls

Exact matches with a well-known name are legitimate; allowlisted names are skipped; names shorter than 5
characters are never compared; names shorter than 8 may differ by 1 edit, longer by 2; internal names are not
compared; established packages get no lookalike floor; similarity is reported as evidence of resemblance,
never as proof of intent. Measured behaviour and remaining false positives: [EVALUATION.md](EVALUATION.md).

## Worked examples (reproduce with `examples/vulnerable-demo`)

| Package | V | S | T | Formula | Floor | Final |
|---|---|---|---|---|---|---|
| `@acme-demo/auth` (public 99.0.0 vs expected 1.4.0) | 100 | 100 | 0 | 0.4*100+0.3*100 = 70 | 80 | **80 CRITICAL** |
| `reqeusts` (looks like `requests`, 1 swap) | 0 | 0 | 87.5 | 26.25 | 60 | **60 HIGH** |
| `acme-demo-reports` (public, same version, not reserved) | 0 | 100 | 0 | 30 | none | **30 MEDIUM** |

## Severity is not the blocking decision

`classify(score)` only maps a score to a band. `policy.fail_on` separately decides which bands block.
Scores are rounded to 2 decimals *before* classification so every report shows the same band for the same number.
Boundary tests: 29.99, 30, 59.99, 60, 79.99, 80 (`tests/test_scoring.py`).
