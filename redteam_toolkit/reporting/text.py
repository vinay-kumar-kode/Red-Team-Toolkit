"""Plain-text rendering of a single report."""

from __future__ import annotations

import textwrap

from ..models import Report


def render_text(report: Report, width: int = 96, show_all: bool = False) -> str:
    lines: list[str] = []
    rule = "=" * width
    thin = "-" * width

    lines.append(rule)
    lines.append(f"MODULE  {report.module}")
    lines.append(f"TARGET  {report.target}")
    lines.append(f"STARTED {report.started_at}")
    lines.append(f"TOOK    {report.duration_seconds:.3f}s")
    lines.append(thin)

    for key, value in _data_lines(report.data):
        lines.append(f"{key:<26}{value}")

    findings = report.sorted_findings()
    lines.append(thin)
    lines.append(f"FINDINGS: {len(findings)}   severity={report.severity}   {report.counts}")
    lines.append(thin)

    if not findings:
        lines.append("  No findings.")
    else:
        for index, finding in enumerate(findings, start=1):
            lines.append(f"{index:>3}. [{finding.severity.upper():<8}] {finding.title}  ({finding.check})")
            if finding.detail:
                lines.extend(_wrap_block("detail", finding.detail, width))
            if finding.remediation:
                lines.extend(_wrap_block("fix", finding.remediation, width))
            if finding.evidence:
                rendered = ", ".join(f"{k}={v}" for k, v in finding.evidence.items())
                lines.extend(_wrap_block("evidence", rendered, width))
            lines.append("")

    return "\n".join(lines)


def _data_lines(data: dict) -> list[tuple[str, str]]:
    """Flatten the data dict into aligned ``key  value`` rows."""
    out: list[tuple[str, str]] = []
    for key, value in data.items():
        if isinstance(value, dict):
            for sub_key, sub_value in value.items():
                out.append((f"  {key}.{sub_key}", _compact(sub_value)))
        elif isinstance(value, (list, tuple)):
            if not value:
                out.append((key, "(empty)"))
            else:
                out.append((key, f"{len(value)} item(s)"))
                for item in value[:20]:
                    out.append((f"    - {_label(item)}", "" if item == "" else _compact(item)[:70]))
                if len(value) > 20:
                    out.append(("    ...", f"{len(value) - 20} more"))
        else:
            out.append((key, _compact(value)))
    return out


def _label(item: object) -> str:
    if isinstance(item, dict):
        return str(item.get("name") or item.get("port") or item.get("id") or next(iter(item.values()), ""))
    return str(item)


def _compact(value: object) -> str:
    if value is None:
        return "-"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, float):
        return f"{value:.4g}"
    if isinstance(value, (dict, list, tuple)):
        import json

        return json.dumps(value, default=str)[:200]
    return str(value)


def _wrap_block(label: str, body: str, width: int) -> list[str]:
    out: list[str] = []
    wrapped = textwrap.wrap(
        body,
        width=max(30, width - 12),
        initial_indent="",
        subsequent_indent="",
    ) or [""]
    for index, line in enumerate(wrapped):
        tag = f"{label}: " if index == 0 else "      "
        out.append(f"     {tag}{line}")
    return out
