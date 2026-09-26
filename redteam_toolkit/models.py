"""Result objects shared by every module.

Every scan module returns a :class:`Report` so the reporting layer, the JSON
exporter and the HTML exporter can treat all modules identically.
"""

from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def severity_rank(severity: str) -> int:
    """Numeric rank for sorting. Unknown severities sort lowest."""
    from .config import SEVERITY_ORDER

    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return -1


@dataclass(slots=True)
class Finding:
    """A single security observation.

    ``check`` is the stable machine identifier, ``title`` the human label,
    ``severity`` the risk rating, and ``remediation`` the concrete fix.
    """

    check: str
    title: str
    severity: str
    detail: str = ""
    remediation: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass(slots=True)
class Report:
    """A module's complete output: what ran, what was found, what to do next."""

    module: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=_utcnow)
    duration_seconds: float = 0.0

    def add(
        self,
        check: str,
        title: str,
        severity: str,
        detail: str = "",
        remediation: str = "",
        **evidence: Any,
    ) -> Finding:
        finding = Finding(
            check=check,
            title=title,
            severity=severity,
            detail=detail,
            remediation=remediation,
            evidence=evidence,
        )
        self.findings.append(finding)
        return finding

    @property
    def severity(self) -> str:
        """Highest severity among findings, or ``info`` when clean."""
        if not self.findings:
            return "info"
        return max((f.severity for f in self.findings), key=severity_rank)

    @property
    def counts(self) -> dict[str, int]:
        counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def at_or_above(self, level: str) -> list[Finding]:
        threshold = severity_rank(level)
        return [f for f in self.findings if severity_rank(f.severity) >= threshold]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: severity_rank(f.severity), reverse=True)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "started_at": self.started_at,
            "duration_seconds": round(self.duration_seconds, 3),
            "severity": self.severity,
            "counts": self.counts,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "data": self.data,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=False, default=str)


class Timer:
    """Context manager recording elapsed wall-clock seconds onto a report."""

    def __init__(self, report: Report) -> None:
        self.report = report
        self._start = 0.0

    def __enter__(self) -> Timer:
        import time

        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        import time

        self.report.duration_seconds = time.perf_counter() - self._start
