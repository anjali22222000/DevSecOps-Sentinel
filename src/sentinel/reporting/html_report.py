"""Self-contained HTML audit report (Jinja2, autoescaped)."""
from __future__ import annotations

from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from sentinel.reporting.json_report import build_report
from sentinel.scanner import ScanResult

_env = Environment(
    loader=PackageLoader("sentinel.reporting", "templates"),
    autoescape=select_autoescape(["html", "j2"], default=True),
    trim_blocks=True, lstrip_blocks=True,
)


def render_html_from_report(report: dict[str, Any]) -> str:
    return _env.get_template("report.html.j2").render(r=report)


def render_html(result: ScanResult) -> str:
    return render_html_from_report(build_report(result))
