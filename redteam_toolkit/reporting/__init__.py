"""Report rendering and persistence.

A run produces one :class:`~redteam_toolkit.models.Report` per module. The
functions here render that into text (terminal), JSON (machine) or HTML (shareable)
and write it to disk.
"""

from __future__ import annotations

import json
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..config import TOOL_NAME, VERSION
from ..models import Finding, Report, severity_rank
from ..utils import console
from .html import render_html
from .text import render_text as render_single_report

__all__ = [
    "Bundle",
    "default_output_dir",
    "print_bundle",
    "render_html",
    "render_json",
    "render_text",
    "write_bundle",
]


def default_output_dir() -> Path:
    """``$RTT_OUTDIR`` if set, else ``reports/`` in the current directory."""
    return Path(os.environ.get("RTT_OUTDIR", "reports"))


@dataclass(slots=True)
class Bundle:
    """Every report produced by one CLI invocation, plus run metadata."""

    command: str
    reports: list[Report] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds"))
    command_line: str = ""

    def add(self, report: Report) -> Report:
        self.reports.append(report)
        return report

    @property
    def findings(self) -> list[Finding]:
        return [f for report in self.reports for f in report.findings]

    @property
    def counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    @property
    def severity(self) -> str:
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=severity_rank)

    def at_or_above(self, level: str) -> list[Finding]:
        threshold = severity_rank(level)
        return [f for f in self.findings if severity_rank(f.severity) >= threshold]

    def to_dict(self) -> dict:
        return {
            "tool": {"name": TOOL_NAME, "version": VERSION},
            "command": self.command,
            "command_line": self.command_line,
            "started_at": self.started_at,
            "severity": self.severity,
            "counts": self.counts,
            # Flattened and sorted, so a consumer does not have to walk every
            # module to answer "what is wrong, most severe first".
            "findings": [
                {**finding.to_dict(), "module": report.module, "target": report.target}
                for report, finding in sorted(
                    ((report, finding) for report in self.reports for finding in report.findings),
                    key=lambda pair: severity_rank(pair[1].severity),
                    reverse=True,
                )
            ],
            "reports": [report.to_dict() for report in self.reports],
        }

    def to_json(self, indent: int = 2) -> str:
        return str(json.dumps(self.to_dict(), indent=indent, default=str))


def render_json(bundle: Bundle) -> str:
    return bundle.to_json()


def render_text(bundle: Bundle, color: bool | None = None, show_all: bool = False) -> str:
    lines: list[str] = []
    for report in bundle.reports:
        lines.append(render_single_report(report))
    lines.append(_summary_text(bundle))
    return "\n".join(lines)


def _summary_text(bundle: Bundle) -> str:
    total = len(bundle.findings)
    counts = bundle.counts
    parts = [
        f"{level}={counts[level]}" for level in ("critical", "high", "medium", "low", "info") if counts[level]
    ]
    breakdown = " ".join(parts) if parts else "clean"
    highest = bundle.severity
    return f"TOTAL {total} finding(s) | {breakdown} | highest: {highest}"


def print_bundle(bundle: Bundle, color: bool | None = None, show_all: bool = False) -> None:
    """Terminal summary across every report in the bundle."""
    console.header(f"{TOOL_NAME} v{VERSION}", f"command: {bundle.command}", color=color)

    if len(bundle.reports) > 1:
        rows = []
        for report in bundle.reports:
            rows.append(
                [
                    report.module,
                    report.target,
                    str(len(report.findings)),
                    str(report.counts["critical"] + report.counts["high"]),
                    f"{report.duration_seconds:.3f}s",
                ]
            )
        print()
        console.kv("per-module results", "", color=color)
        console.table(["module", "target", "findings", "crit+high", "time"], rows, color=color)

    for report in bundle.reports:
        print()
        console.header(report.module, report.target, color=color)
        console.print_report(report, color=color, show_all=show_all)

    counts = bundle.counts
    print()
    console.rule("summary", color=color)
    if bundle.findings:
        chips = "   ".join(
            console.paint(f"{level}={counts[level]}", level, color)
            for level in ("critical", "high", "medium", "low", "info")
            if counts[level]
        )
        console.kv("findings", f"{len(bundle.findings)}  ({chips})", color=color)
        console.kv(
            "highest severity", console.paint(bundle.severity.upper(), bundle.severity, color), color=color
        )
    else:
        console.kv("findings", "none", color=color)


def write_bundle(
    bundle: Bundle,
    output_dir: str | Path | None = None,
    basename: str | None = None,
    formats: Sequence[str] = ("json", "html", "txt"),
) -> list[Path]:
    """Write the bundle in each requested format. Returns the paths written."""
    directory = Path(output_dir) if output_dir else default_output_dir()
    directory.mkdir(parents=True, exist_ok=True)

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    stem = basename or f"rtt-{bundle.command}-{stamp}"

    written: list[Path] = []
    for fmt in formats:
        if fmt == "json":
            path = directory / f"{stem}.json"
            path.write_text(render_json(bundle) + "\n", encoding="utf-8")
        elif fmt == "html":
            path = directory / f"{stem}.html"
            path.write_text(render_html(bundle), encoding="utf-8")
        elif fmt == "txt":
            path = directory / f"{stem}.txt"
            path.write_text(render_text(bundle, color=False) + "\n", encoding="utf-8")
        else:
            raise ValueError(f"unknown report format: {fmt!r}")
        written.append(path)
    return written
