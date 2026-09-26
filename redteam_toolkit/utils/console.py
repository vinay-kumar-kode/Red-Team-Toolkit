"""Terminal output: colour, severity badges, tables, progress.

Colour is auto-disabled when stdout is not a TTY, when ``NO_COLOR`` is set, or
when ``--no-color`` is passed, so piped output stays clean.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Iterable, Sequence
from typing import IO

from ..config import SEVERITY_ORDER
from ..models import Finding, Report

RESET = "\033[0m"
COLORS = {
    "critical": "\033[1;97;41m",
    "high": "\033[1;31m",
    "medium": "\033[1;33m",
    "low": "\033[1;36m",
    "info": "\033[1;32m",
    "accent": "\033[1;35m",
    "dim": "\033[2m",
    "bold": "\033[1m",
    "ok": "\033[1;32m",
    "warn": "\033[1;33m",
    "bad": "\033[1;31m",
}

_ASCII = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED",
    "low": "LOW",
    "info": "INFO",
    "arrow": "->",
    "bullet": "*",
    "ok": "[ok]",
    "warn": "[!]",
    "bad": "[x]",
    "rule": "-",
    "open": "+",
    "closed": "-",
}


#: Set by ``--no-color`` / ``--json`` so every helper below respects it without
#: each call site having to thread a flag through.
_OVERRIDE: bool | None = None


def enable_color(force: bool | None = None) -> bool:
    """Report whether colour should be used.

    An explicit ``force`` wins, then any override set by :func:`set_color`,
    then ``NO_COLOR`` / ``FORCE_COLOR``, then whether stdout is a terminal.
    """
    if force is not None:
        return force
    if _OVERRIDE is not None:
        return _OVERRIDE
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def set_color(enabled: bool | None) -> None:
    """Set (or clear, with ``None``) the process-wide colour override."""
    global _OVERRIDE
    _OVERRIDE = enabled


#: When true every print helper in this module is a no-op. The CLI turns this on
#: for ``--json`` so stdout carries the JSON document and nothing else, which is
#: what makes ``rtt scan ... --json | jq`` work.
_QUIET = False


def set_quiet(quiet: bool) -> None:
    global _QUIET
    _QUIET = quiet


def is_quiet() -> bool:
    return _QUIET


def emit(text: str = "", stream: IO[str] | None = None) -> None:
    """Print unless quiet mode is on."""
    if _QUIET:
        return
    print(text, file=stream or sys.stdout)


def resolve(force: bool | None = None) -> bool:
    """Normalise a ``color=`` argument on any helper to a definite answer."""
    return enable_color(force)


def paint(text: str, style: str, color: bool | None = None) -> str:
    if not resolve(color) or style not in COLORS:
        return text
    return f"{COLORS[style]}{text}{RESET}"


def term_width(default: int = 100) -> int:
    if not sys.stdout.isatty():
        return default
    try:
        return max(60, min(shutil.get_terminal_size((default, 24)).columns, 160))
    except OSError:
        return default


def glyph(kind: str, color: bool | None = None) -> str:
    return _ASCII.get(kind, _ASCII["bullet"])


def severity_badge(severity: str, color: bool | None = None) -> str:
    label = _ASCII.get(severity, severity.upper()[:4])
    return paint(f" {label} ", severity, color)


def rule(title: str = "", width: int | None = None, color: bool | None = None) -> str:
    width = width or term_width()
    if not title:
        return paint("-" * width, "dim", color)
    head = f"-- {title} "
    tail = "-" * max(0, width - len(head))
    return paint(head + tail, "dim", color)


def header(title: str, subtitle: str = "", color: bool | None = None) -> None:
    if _QUIET:
        return
    print()
    print(paint(rule(title, color=color), "accent", color))
    if subtitle:
        print(paint(f"   {subtitle}", "dim", color))


def info(message: str, color: bool | None = None) -> None:
    emit(f"   {paint(glyph('bullet'), 'dim', color)} {message}")


def success(message: str, color: bool | None = None) -> None:
    emit(f"   {paint(glyph('ok'), 'ok', color)} {message}")


def warn(message: str, color: bool | None = None) -> None:
    emit(f"   {paint(glyph('warn'), 'warn', color)} {message}")


def error(message: str, color: bool | None = None) -> None:
    # Errors go to stderr, which stays meaningful even in quiet mode.
    print(f"   {paint(glyph('bad'), 'bad', color)} {message}", file=sys.stderr)


def kv(key: str, value: object, width: int = 22, color: bool | None = None) -> None:
    emit(f"   {paint(key.ljust(width), 'dim', color)} {value}")


def table(
    headers: Sequence[str],
    rows: Iterable[Sequence[object]],
    color: bool | None = None,
    indent: str = "   ",
) -> None:
    """Render a fixed-width table. Empty rows print a single muted line."""
    if _QUIET:
        return

    materialised = [[("" if c is None else str(c)) for c in row] for row in rows]
    if not materialised:
        print(indent + paint("(none)", "dim", color))
        return

    columns = len(headers)
    widths = [len(str(h)) for h in headers]
    for row in materialised:
        for index in range(columns):
            widths[index] = max(widths[index], _visible_len(str(row[index])))

    # Shrink the widest column repeatedly until the table fits. Trimming only the
    # single widest column leaves a table with two or more over-wide columns
    # overflowing, which is exactly the case long banners produce.
    budget = term_width() - len(indent) - 2 * (columns - 1)
    min_width = 8
    while sum(widths) > budget:
        widest = widths.index(max(widths))
        if widths[widest] <= min_width:
            break
        widths[widest] -= 1

    def render(cells: Sequence[str], style: str = "") -> str:
        out = []
        for index in range(columns):
            text = _clip(cells[index], widths[index])
            out.append(text.ljust(widths[index]))
        line = "  ".join(out).rstrip()
        return paint(line, style, color) if style else line

    print(indent + render([str(h) for h in headers]))
    print(indent + paint("  ".join("-" * w for w in widths), "dim", color))
    for row in materialised:
        print(indent + render(row))


def _visible_len(text: str) -> int:
    """Length ignoring ANSI escapes, so coloured cells align."""
    out = 0
    index = 0
    while index < len(text):
        if text[index] == "\033":
            end = text.find("m", index)
            index = len(text) if end == -1 else end + 1
            continue
        out += 1
        index += 1
    return out


def _clip(text: str, width: int) -> str:
    if _visible_len(text) <= width:
        return text
    out = 0
    index = 0
    while index < len(text) and out < width - 1:
        if text[index] == "\033":
            end = text.find("m", index)
            index = len(text) if end == -1 else end + 1
            continue
        out += 1
        index += 1
    return text[:index] + "\033[0m~"


def print_findings(findings: Sequence[Finding], color: bool | None = None, limit: int | None = None) -> None:
    if _QUIET:
        return
    if not findings:
        success("No findings. Nothing to remediate.", color)
        return

    shown = findings if limit is None else findings[:limit]
    for finding in shown:
        badge = severity_badge(finding.severity, color)
        print(
            f"   {badge} {paint(finding.title, 'bold', color)}  {paint('(' + finding.check + ')', 'dim', color)}"
        )
        if finding.detail:
            for line in _wrap(finding.detail, term_width() - 10):
                print(f"        {line}")
        if finding.remediation:
            for index, line in enumerate(_wrap(finding.remediation, term_width() - 10)):
                prefix = "fix: " if index == 0 else "     "
                print(f"        {paint(prefix + line, 'dim', color)}")
        print()

    if limit is not None and len(findings) > limit:
        print(paint(f"   ... {len(findings) - limit} more (raise --show-all or use --json)", "dim", color))


def print_report(report: Report, color: bool | None = None, show_all: bool = False) -> None:
    if _QUIET:
        return
    findings = report.sorted_findings()
    print()
    print(paint(f"Findings ({len(findings)})", "bold", color))
    if findings:
        counts = report.counts
        chips = "  ".join(
            paint(f"{level}={counts[level]}", level, color) for level in SEVERITY_ORDER if counts[level]
        )
        print(f"   {chips}")
        print()
        print_findings(findings, color, limit=None if show_all else 12)
    else:
        success("None.", color)


def _wrap(text: str, width: int) -> list[str]:
    import textwrap

    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        wrapped = textwrap.wrap(paragraph, width=max(20, width)) or [""]
        lines.extend(wrapped)
    return lines
