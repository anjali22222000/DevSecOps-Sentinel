#!/usr/bin/env python3
"""Regenerate the numbers in docs/FINAL_REPORT_DRAFT.md from the generated measurement files.

Run after: summarize_tests.py, run_scenarios.py, benchmark.py, evaluate_similarity.py.
Only the figures are refreshed (the text of the draft is yours to edit): this script rewrites the
lines that quote results by regex, so prose you changed elsewhere is kept.
"""
from __future__ import annotations

import pathlib
import re
import sys

D = pathlib.Path(__file__).resolve().parents[1] / "docs"


def grab(pattern: str, text: str, what: str):
    m = re.search(pattern, text)
    if not m:
        sys.exit(f"cannot find {what}; run the generator scripts first")
    return m


tests = grab(r"\*\*(\d+) passed, (\d+) failed, (\d+) skipped, (\d+) total", (D / "TEST_RESULTS.md").read_text(), "test totals")
scen = grab(r"\*\*Result: (\d+) of (\d+) scenarios matched", (D / "SCENARIOS.md").read_text(), "scenario result")
perf = (D / "PERFORMANCE.md").read_text()
live = grab(r"min / median / max: \*\*([\d.]+) s / ([\d.]+) s / ([\d.]+) s\*\*", perf, "live timing")
rows = re.findall(r"\| (\d+) \| (\d+) \| ([\d.]+) s \| ([\d.]+) s \| ([\d.]+) ms \| ([\d.]+) ms \|", perf)
table = "\n".join(f"| {n} | {c} | {l} s | {i} s |" for n, c, l, i, _, _ in rows)

path = D / "FINAL_REPORT_DRAFT.md"
text = path.read_text()
text = re.sub(r"The implementation has \d+ automated tests passing and \d+ of \d+ recorded",
              f"The implementation has {tests[1]} automated tests passing and {scen[1]} of {scen[2]} recorded", text)
text = re.sub(r"\*\*Automated tests:\*\* \d+ passed, \d+ failed, \d+ skipped \(\d+ total\)",
              f"**Automated tests:** {tests[1]} passed, {tests[2]} failed, {tests[3]} skipped ({tests[4]} total)", text)
text = re.sub(r"\*\*End-to-end scenarios:\*\* \d+ of \d+ matched", f"**End-to-end scenarios:** {scen[1]} of {scen[2]} matched", text)
text = re.sub(r"(\| Packages \| Concurrency \| Median lookup time \| Ideal \|\n\|---\|---\|---\|---\|\n)(?:\|.*\|\n)+",
              lambda m: m.group(1) + table + "\n", text)
text = re.sub(r"took [\d.]+ / [\d.]+ / [\d.]+ s \(min / median / max of 5",
              f"took {live[1]} / {live[2]} / {live[3]} s (min / median / max of 5", text)
path.write_text(text)
print("figures refreshed:", tests.groups(), scen.groups(), live.groups())
