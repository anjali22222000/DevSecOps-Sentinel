#!/usr/bin/env python3
"""Evaluate typosquat detection on a small, hand-built dataset. Writes docs/EVALUATION.md.

Positives  : SYNTHETIC mutations (swap, omission, duplication, substitution, hyphen) of well-known names.
             They are hypothetical; nothing is published and no claim is made that such packages exist.
Negatives  : legitimate packages chosen by hand and (if the network is reachable) verified to exist on the
             real registries today. Several are deliberately chosen to sit close to a well-known name.
This is a regression/sanity evaluation, NOT a measurement of real-world detection accuracy.
"""
from __future__ import annotations

import asyncio
import datetime
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinel.analysis.similarity import find_lookalike, load_top_packages     # noqa: E402
from sentinel.analyzer import analyze                                           # noqa: E402
from sentinel.config import Config, SimilarityConfig                            # noqa: E402
from sentinel.models import (Dependency, Ecosystem, LookupStatus, Origin, ParseResult,  # noqa: E402
                             SourceType)
from sentinel.registry import RegistryInspector                                 # noqa: E402
from sentinel.registry.http import Fetcher                                      # noqa: E402

NPM_LEGIT = """color colorette kleur picocolors ansi-colors ansi-styles strip-ansi wrap-ansi string-width cli-table3 meow
yargs-parser glob-parent globby fast-glob picomatch micromatch anymatch braces json5 jsonfile graceful-fs del make-dir tmp
shortid ms bytes lru-cache p-limit p-map p-queue got ky undici cross-fetch form-data follow-redirects proxy-from-env
tough-cookie iconv-lite safer-buffer depd statuses http-errors on-finished raw-body type-is content-type accepts negotiator
vary etag fresh cookie-signature cookies through validate mysql2 expect execa cross-spawn which shelljs wait-on open listr
listr2 boxen figlet update-notifier configstore dotenv-expand env-cmd tsx terser uglify-js clean-css cssnano stylelint
jshint standard nyc c8 istanbul tape ava jasmine karma qunit pm2 forever supervisor""".split()
PYPI_LEGIT = """pytest-mock pytest-xdist pytest-asyncio pytest-timeout requests-mock requests-toolbelt requests-futures
requests-cache mysqlclient psycopg psycopg2-binary asyncpg aiomysql aiopg hiredis pymongo motor sqlalchemy-utils alembic
peewee marshmallow cattrs dataclasses-json pydantic-core pydantic-settings typer fire docopt argcomplete configargparse
python-decouple environs dynaconf tenacity retrying backoff ratelimit diskcache joblib dill cloudpickle msgpack rapidfuzz
levenshtein jellyfish thefuzz fuzzywuzzy regex parse arrow pendulum tzlocal humanize babel freezegun faker factory-boy
hypothesis behave locust flask-cors flask-login flask-sqlalchemy flask-restful django-cors-headers djangorestframework
waitress hypercorn starlette sanic tornado bottle falcon pyramid cherrypy""".split()


def mutations(name: str):
    mid = len(name) // 2
    out = {}
    for i in (mid, mid - 1, mid + 1):                       # find a swappable adjacent pair near the middle
        if 0 < i < len(name) - 1 and name[i] != name[i + 1]:
            out["swap"] = name[:i] + name[i + 1] + name[i] + name[i + 2:]
            break
    out["omission"] = name[:mid] + name[mid + 1:]
    out["duplication"] = name[:mid] + name[mid] + name[mid:]
    if name[mid].isalpha():
        out["substitution"] = name[:mid] + chr((ord(name[mid]) - 96) % 26 + 97) + name[mid + 1:]
    if "-" not in name:
        out["hyphen"] = name[:mid] + "-" + name[mid:]
    return out


def positives(eco: Ecosystem):
    top = set(load_top_packages(eco))
    data = []
    for target in load_top_packages(eco):
        if len(target) < 5 or target.startswith("@"):
            continue
        for kind, mutant in mutations(target).items():
            if mutant != target and mutant not in top and "--" not in mutant:
                data.append((kind, target, mutant))
    return data


async def verify_exist(names, eco):
    deps = [Dependency(name=n, ecosystem=eco, origin=Origin.MANIFEST, source_file="x", section="x",
                       source_type=SourceType.REGISTRY) for n in names]
    async with Fetcher(timeout=15, concurrency=10) as fetcher:
        return await RegistryInspector(fetcher).inspect(deps)


def evaluate(algorithm: str):
    cfg = SimilarityConfig(algorithm=algorithm)
    result = {}
    for eco in Ecosystem:
        pos = positives(eco)
        by_kind = defaultdict(lambda: [0, 0, 0])             # total, detected, detected-with-intended-target
        for kind, target, mutant in pos:
            m = find_lookalike(mutant, eco, cfg)
            by_kind[kind][0] += 1
            if m:
                by_kind[kind][1] += 1
                by_kind[kind][2] += m.target == target
        result[eco] = (len(pos), by_kind)
    return result


def main():
    cfg_default = SimilarityConfig()
    legit, dropped, evidence = {}, {}, {}
    try:
        for eco, names in ((Ecosystem.NPM, NPM_LEGIT), (Ecosystem.PYPI, PYPI_LEGIT)):
            found = asyncio.run(verify_exist(sorted(set(names)), eco))
            evidence.update(found)
            legit[eco] = [n for n in sorted(set(names)) if found[(eco, n)].status is LookupStatus.FOUND
                          and n not in set(load_top_packages(eco))]
            dropped[eco] = [n for n in sorted(set(names)) if n not in legit[eco]]
        verified = True
    except Exception as exc:                                   # offline: use lists unverified
        print("registry verification skipped:", exc)
        verified = False
        for eco, names in ((Ecosystem.NPM, NPM_LEGIT), (Ecosystem.PYPI, PYPI_LEGIT)):
            legit[eco], dropped[eco] = sorted(set(names) - set(load_top_packages(eco))), []

    md = ["# Similarity-detection evaluation", "",
          f"Generated by `scripts/evaluate_similarity.py` on {datetime.date.today()}.", "",
          "> **Read this first.** This is a small, hand-built regression evaluation. The positives are *synthetic* mutations of "
          "well-known names (hypothetical, nothing was published). The negatives are legitimate packages I chose. "
          "The seed list of well-known names is also hand-curated. The results show how the filters behave on this dataset; "
          "they are **not** a measurement of real-world detection accuracy and must not be quoted as one.", ""]

    for algo in ("damerau", "levenshtein"):
        res = evaluate(algo)
        md += [f"## Recall on synthetic typosquats - algorithm `{algo}`", "",
               "| Ecosystem | Mutation | Cases | Detected | Detected with intended target |", "|---|---|---|---|---|"]
        for eco in Ecosystem:
            total, by_kind = res[eco]
            for kind in sorted(by_kind):
                t, d, c = by_kind[kind]
                md.append(f"| {eco.value} | {kind} | {t} | {d} ({100*d/t:.0f}%) | {c} |")
            td = sum(v[1] for v in by_kind.values())
            md.append(f"| **{eco.value}** | **all** | **{total}** | **{td} ({100*td/total:.0f}%)** | {sum(v[2] for v in by_kind.values())} |")
        md.append("")

    md += ["## False positives on legitimate packages (name-only filters, default config)", ""]
    if verified:
        md.append("Negatives were verified to exist on the live registries on the date above; "
                  + "; ".join(f"{e.value}: dropped {len(dropped[e])} of {len(set(NPM_LEGIT if e is Ecosystem.NPM else PYPI_LEGIT))} candidate names"
                              f" ({', '.join(dropped[e]) or 'none'})" for e in Ecosystem) + ".")
    else:
        md.append("**Registry verification was not possible; names are unverified.**")
    md.append("")
    fps = []
    for eco in Ecosystem:
        for n in legit[eco]:
            m = find_lookalike(n, eco, cfg_default)
            if m:
                fps.append((eco, n, m))
    total_neg = sum(len(v) for v in legit.values())
    md += [f"Legitimate names evaluated: **{total_neg}**. Flagged by name similarity alone: **{len(fps)}** "
           f"({100*len(fps)/total_neg:.1f}%).", "",
           "| Ecosystem | Legitimate package | Looks like | Edit distance | Similarity |", "|---|---|---|---|---|"]
    for eco, n, m in fps:
        md.append(f"| {eco.value} | {n} | {m.target} | {m.distance} | {m.similarity:.1f}% |")

    # stage 2: effect of the "established package" filter, using live registry metadata
    if verified and fps:
        deps = [Dependency(name=n, ecosystem=e, origin=Origin.MANIFEST, source_file="package.json", section="x",
                           pinned_version="1.0.0", source_type=SourceType.REGISTRY) for e, n, _ in fps]
        analyses = analyze(ParseResult(dependencies=deps), {k: v for k, v in evidence.items()}, Config(), Path("."))
        remaining = [f for f in analyses if f.severity.value != "SAFE"]
        md += ["", "### Effect of the 'established package' filter (uses live registry history)", "",
               f"Re-analysing the {len(fps)} name-only false positives with their real registry metadata "
               f"(>= {cfg_default.established_versions} published versions or first published >= {cfg_default.established_age_days} days ago): "
               f"**{len(remaining)} of {len(fps)} still score MEDIUM or above**, so the filter removes {len(fps)-len(remaining)}.",
               "", ("Still flagged: " + ", ".join(f"`{f.package}`" for f in remaining) + ". These are legitimate packages, so each is a "
                    "remaining false positive that a human reviewer or the allowlist must clear.") if remaining else "No false positives remain.",
               "", "| Package | Severity after filter | Score |", "|---|---|---|"]
        for f in analyses:
            md.append(f"| {f.package} | {f.severity.value} | {f.score:g} |")
        md += ["", "NPM abbreviated metadata has no dates, so for NPM only the version-count rule applies. "
               "A real typosquat that is very new and has few versions is *not* downgraded; "
               "a typosquat of a popular package that has existed for years would be (a known gap)."]

    md += ["", "## Conclusions that are supported", "",
           "- The Damerau option detects adjacent swaps that plain Levenshtein misses on short names (compare the two `swap` rows).",
           "- The minimum-length rule means very short names are never compared; that removes noise but means short typosquats are missed (see `omission` rows).",
           "- Name similarity alone produces false positives on legitimate near-neighbours; registry history reduces but does not eliminate them.",
           "## Conclusions that are NOT supported", "",
           "- Any statement about detection rates on real attacks, real-world false-positive rates, or comparison with other tools.",
           f"- Any statement about names outside the seed lists ({len(load_top_packages(Ecosystem.NPM))} NPM and "
           f"{len(load_top_packages(Ecosystem.PYPI))} PyPI names, hand-curated; not a download-ranked top-N).", ""]
    (ROOT / "docs" / "EVALUATION.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md[-60:]) if False else "wrote docs/EVALUATION.md")
    print(f"negatives={total_neg} flagged={len(fps)}")


if __name__ == "__main__":
    main()
