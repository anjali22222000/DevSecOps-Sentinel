"""Command-line interface.

Exit codes: 0 = pass, 1 = policy block (a finding reached the blocking threshold),
2 = scanner error (bad input, bad config, registry failure). An error is never a pass.
"""
from __future__ import annotations

import argparse
import asyncio
import dataclasses
import json
import logging
import sys
from collections import Counter
from importlib import resources
from pathlib import Path

from sentinel import __version__
from sentinel.config import FAIL_ON_LEVELS, Config, ConfigError, load_config
from sentinel.models import Dependency, LookupStatus, Severity
from sentinel.parsers import scan_directory
from sentinel.policy import EXIT_ERROR, EXIT_OK, EXIT_POLICY_BLOCK
from sentinel.registry import RegistryInspector
from sentinel.registry.fixture import FixtureError, load_fixture
from sentinel.registry.http import Fetcher
from sentinel.reporting.html_report import render_html_from_report
from sentinel.reporting.json_report import build_report
from sentinel.reporting.sarif import render_sarif
from sentinel.scanner import ScanResult, build_result, split_for_lookup

__all__ = ["main", "EXIT_OK", "EXIT_POLICY_BLOCK", "EXIT_ERROR"]

log = logging.getLogger("sentinel")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sentinel", description="DevSecOps Sentinel")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="scan a project directory before installing its dependencies")
    scan.add_argument("path", help="project directory to scan")
    scan.add_argument("--config", help="path to sentinel.toml (default: <path>/sentinel.toml if present)")
    scan.add_argument("--format", choices=("text", "json"), default="text", help="stdout format")
    source = scan.add_mutually_exclusive_group()
    source.add_argument("--registry", action="store_true",
                        help="query public registries (sends package names to npmjs.org and pypi.org)")
    source.add_argument("--registry-fixture", metavar="FILE",
                        help="use registry answers from a local JSON file (demos and tests; no network)")
    scan.add_argument("--fail-on", choices=FAIL_ON_LEVELS, help="override policy.fail_on")
    scan.add_argument("--output-dir", help="write report.json, report.html, report.sarif and dashboard.html here")
    scan.add_argument("--list-dependencies", action="store_true", help="include the parsed dependency table")
    scan.add_argument("--timeout", type=float, help="per-request timeout in seconds")
    scan.add_argument("--concurrency", type=int, help="maximum parallel requests")
    scan.add_argument("-v", "--verbose", action="store_true", help="debug logging to stderr")
    return parser


async def _inspect(dependencies: list[Dependency], timeout: float, concurrency: int):
    async with Fetcher(timeout=timeout, concurrency=concurrency) as fetcher:
        return await RegistryInspector(fetcher).inspect(dependencies)


def _where(diag) -> str:
    return f"{diag.file}:{diag.line}: " if diag.line else f"{diag.file}: "


def _print_text(result: ScanResult, list_dependencies: bool) -> None:
    parse = result.parse
    counts = result.severity_counts()
    partial = sum(1 for f in result.findings if f.assessment == "partial")
    print(f"Scan root: {result.root}")
    print(f"Dependencies: {len(parse.dependencies)}  Registry options: {len(parse.registry_options)}  "
          f"Warnings: {len(parse.warnings)}  Errors: {len(result.errors)}")
    print(f"Registry mode: {result.registry_mode}")
    if result.registry_mode != "off":
        lookups = Counter(e.status.value for e in result.evidence)
        print(f"Registry lookups: {len(result.evidence)}  "
              + "  ".join(f"{s.value}: {lookups.get(s.value, 0)}" for s in LookupStatus))
    print("Findings: " + "  ".join(f"{s.value} {counts[s.value]}" for s in
                                   (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.SAFE))
          + f"  (partial evidence: {partial})")

    if list_dependencies and parse.dependencies:
        print()
        print(f"{'ECOSYSTEM':<10}{'NAME':<34}{'VERSION / SPEC':<30}{'ORIGIN':<10}SECTION")
        for d in sorted(parse.dependencies, key=lambda d: (
                d.ecosystem.value, d.name, d.origin.value, d.pinned_version or d.version_spec)):
            name = d.name if d.alias is None else f"{d.name} (as {d.alias})"
            version = d.pinned_version or d.version_spec or "-"
            if d.source_type.value != "registry":
                version = f"{version} [{d.source_type.value}]"
            print(f"{d.ecosystem.value:<10}{name:<34}{version:<30}{d.origin.value:<10}{d.section}")
    if parse.registry_options:
        print("\nRegistry options:")
        for o in parse.registry_options:
            print(f"  {o.source_file}:{o.line}  {o.kind} {o.value}".rstrip())

    flagged = [f for f in result.findings if f.severity is not Severity.SAFE]
    if flagged:
        print(f"\n{'ID':<6}{'SEVERITY':<10}{'SCORE':<7}{'ITEM':<34}WHY")
        for f in flagged:
            print(f"{f.id:<6}{f.severity.value:<10}{f.score:<7g}{(f.package or 'configuration'):<34}"
                  f"{f.reason}")

    d = result.decision
    verdict = {0: "PASS", 1: "BLOCKED", 2: "SCANNER ERROR"}[d.exit_code]
    print(f"\nPolicy: {verdict} (exit {d.exit_code}); fail_on={d.fail_on}; " + "; ".join(d.reasons))

    for diag in parse.warnings:
        print(f"warning: {_where(diag)}{diag.message}", file=sys.stderr)
    for diag in result.errors:
        print(f"error: {_where(diag)}{diag.message}", file=sys.stderr)


def _write_reports(result: ScanResult, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    report = build_report(result)
    (out_dir / "report.json").write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (out_dir / "report.html").write_text(render_html_from_report(report), encoding="utf-8")
    (out_dir / "report.sarif").write_text(render_sarif(result), encoding="utf-8")
    dashboard = resources.files("sentinel.dashboard").joinpath("index.html").read_text(encoding="utf-8")
    (out_dir / "dashboard.html").write_text(dashboard, encoding="utf-8")


def _resolve_config(args: argparse.Namespace, root: Path) -> Config:
    path = Path(args.config) if args.config else (root / "sentinel.toml")
    if args.config is None and not path.is_file():
        config = load_config(None)
    else:
        config = load_config(path)
    if args.fail_on:
        config = dataclasses.replace(config, policy=dataclasses.replace(config.policy, fail_on=args.fail_on))
    return config


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    root = Path(args.path)
    if not root.is_dir():
        print(f"error: '{root}' is not a directory", file=sys.stderr)
        return EXIT_ERROR
    try:
        config = _resolve_config(args, root)
    except ConfigError as exc:
        print(f"error: configuration: {exc}", file=sys.stderr)
        return EXIT_ERROR

    parse = scan_directory(root)
    log.debug("parsed %d dependencies, %d options", len(parse.dependencies), len(parse.registry_options))

    evidence_map: dict = {}
    mode, source = "off", None
    if args.registry or args.registry_fixture:
        queryable, skipped = split_for_lookup(parse.dependencies, config)
        if args.registry:
            timeout = args.timeout or config.registry.timeout
            concurrency = args.concurrency or config.registry.concurrency
            try:
                found = asyncio.run(_inspect(queryable, timeout, concurrency))
            except Exception as exc:  # a bug, not a registry problem: fail loudly, never pass
                print(f"error: registry inspection failed: {type(exc).__name__}: {exc}", file=sys.stderr)
                return EXIT_ERROR
            mode = "live"
        else:
            try:
                found = load_fixture(Path(args.registry_fixture), queryable)
            except FixtureError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return EXIT_ERROR
            mode, source = "fixture", Path(args.registry_fixture).name
        evidence_map = {**found, **skipped}

    result = build_result(root, config, parse, evidence_map, mode, source)

    if args.output_dir:
        try:
            _write_reports(result, Path(args.output_dir))
        except OSError as exc:
            print(f"error: cannot write reports: {exc}", file=sys.stderr)
            return EXIT_ERROR

    if args.format == "json":
        print(json.dumps(build_report(result), indent=2, ensure_ascii=False))
        for diag in result.errors:
            print(f"error: {_where(diag)}{diag.message}", file=sys.stderr)
    else:
        _print_text(result, args.list_dependencies)
        if args.output_dir:
            print(f"Reports written to {args.output_dir}/ (report.json, report.html, report.sarif, dashboard.html)")
    return result.decision.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
