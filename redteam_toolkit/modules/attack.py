"""Automated assessment workflow.

Runs the individual modules in the order an assessor would, and rolls their
output up into an attack-surface summary: which services are reachable, what an
attacker could try first, and what to fix in priority order.

On the credential stage: this workflow does not authenticate against the target.
It reads a combo wordlist, scores the passwords in it offline, and reports how
many attempts an attacker would need and how much time that costs. That answers
the question an assessor actually has ("how bad is this list?") without
generating live credential-stuffing traffic against a third party's host.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field

from ..config import CREDENTIAL_SERVICES
from ..models import Finding, Report, severity_rank
from ..reporting import Bundle
from ..utils import console
from ..utils.net import guess_url_scheme
from . import password as password_mod
from . import scanner, tls_audit, webscan

STAGES = ("recon", "credential", "web", "tls", "prioritise")


@dataclass(slots=True)
class StageRecord:
    name: str
    status: str
    seconds: float
    summary: str
    findings: int = 0
    error: str = ""


@dataclass(slots=True)
class Assessment:
    """Everything the workflow produced, ready for reporting."""

    target: str
    address: str
    bundle: Bundle
    stages: list[StageRecord] = field(default_factory=list)
    open_ports: list[int] = field(default_factory=list)
    services: dict[str, list[int]] = field(default_factory=dict)
    attack_surface: list[dict] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)

    @property
    def seconds(self) -> float:
        return time.time() - self.started_at

    def record(
        self, name: str, status: str, seconds: float, summary: str, findings: int = 0, error: str = ""
    ) -> StageRecord:
        record = StageRecord(name, status, seconds, summary, findings, error)
        self.stages.append(record)
        return record

    def report(self) -> Report:
        """A single roll-up report describing the whole run."""
        report = Report(module="attack", target=self.target)
        report.data["address"] = self.address
        report.data["duration_seconds"] = round(self.seconds, 2)
        report.data["stages"] = [
            {
                "stage": s.name,
                "status": s.status,
                "seconds": round(s.seconds, 2),
                "findings": s.findings,
                "summary": s.summary,
                "error": s.error,
            }
            for s in self.stages
        ]
        report.data["open_ports"] = self.open_ports
        report.data["services"] = self.services
        report.data["attack_surface"] = self.attack_surface
        report.data["total_findings"] = len(self.bundle.findings)
        report.data["counts"] = self.bundle.counts
        report.data["credential_stage"] = (
            "Offline wordlist analysis only. No authentication attempt is made against the target."
        )
        self._add_priorities(report)
        return report

    def _add_priorities(self, report: Report) -> None:
        if not self.attack_surface:
            return

        top = sorted(self.attack_surface, key=lambda item: -item["priority"])[:3]
        report.add(
            check="flow.attack-path",
            title="Most likely initial-access paths, in order",
            severity="high" if top and top[0]["priority"] >= 7 else "medium",
            detail=(
                "Ranked by how much an attacker gains per step: "
                + " -> ".join(f"{item['service']}:{item['port']} ({item['priority']}/10)" for item in top)
                + ". "
                + "Ranks are a triage aid computed from exposure, protocol weakness and "
                "credential exposure, not a measured exploit."
            ),
            remediation="Close or restrict the highest-ranked service first; re-run to confirm the rank drops.",
            ranked=[f"{item['service']}:{item['port']}" for item in top],
        )

        anonymous = [item for item in self.attack_surface if "anonymous" in item["reasons"]]
        if anonymous:
            report.add(
                check="flow.anonymous-access",
                title=f"{len(anonymous)} service(s) may be reachable without credentials",
                severity="critical",
                detail=(
                    "Reachable: "
                    + ", ".join(f"{item['service']}:{item['port']}" for item in anonymous)
                    + ". Anonymous access means an attacker skips the credential stage entirely."
                ),
                remediation="Verify with an unauthenticated client, then require authentication and disable guest access.",
                services=[f"{i['service']}:{i['port']}" for i in anonymous],
            )

        for item in self.attack_surface:
            if item["credential_exposed"]:
                report.add(
                    check="flow.credential-surface",
                    title=f"{item['service']} on port {item['port']} accepts cleartext credentials",
                    severity="high",
                    detail=(
                        f"{item['service']} transmits usernames and passwords without encryption, so "
                        "the credential stage is cheap: a single packet capture during login yields "
                        "working credentials for every other service that reuses them."
                    ),
                    remediation="Move to SSH, SFTP or a TLS-wrapped equivalent and rotate any password ever sent over it.",
                    service=item["service"],
                    port=item["port"],
                )


def run(
    target: str,
    address: str,
    ports: str | list[int] | None = None,
    wordlist: str | None = None,
    timeout: float = 1.0,
    workers: int = 64,
    http_timeout: float = 10.0,
    verify_tls: bool = True,
    check_paths: bool = True,
    cve_db: str | None = None,
    on_progress: Callable[[str, str], None] | None = None,
) -> Assessment:
    """Run the full workflow and return the :class:`Assessment`."""
    assessment = Assessment(target=target, address=address, bundle=Bundle(command="attack"))
    announce = on_progress or (lambda stage, message: None)

    # --- stage 1: reconnaissance -----------------------------------------
    announce("recon", f"scanning {address}")
    console.header("Stage 1/5  Reconnaissance", f"target {address}", color=console.enable_color())
    started = time.time()
    try:
        recon = scanner.scan(target, address, ports=ports, timeout=timeout, workers=workers)
        assessment.bundle.add(recon)
        assessment.open_ports = recon.data["open_ports"]
        assessment.services = _group_services(recon)
        assessment.record(
            "recon",
            "ok",
            time.time() - started,
            f"{len(assessment.open_ports)} open port(s), {len(assessment.services)} service type(s)",
            len(recon.findings),
        )
    except Exception as exc:  # a failed stage must not abort the run
        assessment.record("recon", "error", time.time() - started, "scanner failed", 0, str(exc))
        return assessment

    if not assessment.open_ports:
        assessment.record("prioritise", "ok", 0.0, "no open ports; nothing further to assess")
        return assessment

    # --- stage 2: credential exposure (offline) --------------------------
    announce("credential", "analysing wordlist offline")
    console.header(
        "Stage 2/5  Credential exposure", "offline analysis, no login attempts", color=console.enable_color()
    )
    started = time.time()
    credential_summary = "skipped (no --wordlist)"
    credential_findings = 0
    if wordlist:
        cred_report = password_mod.combo_estimate(wordlist)
        assessment.bundle.add(cred_report)
        credential_findings = len(cred_report.findings)
        credential_summary = (
            f"{cred_report.data.get('wellformed_combos', 0)} combo(s) scored offline, "
            f"{cred_report.data.get('weak_password_count', 0)} with trivial passwords"
        )
    assessment.record("credential", "ok", time.time() - started, credential_summary, credential_findings)

    # --- stage 3: web ----------------------------------------------------
    # Discovery drives this, not a fixed port list: the scanner reports any open
    # port that answered an HTTP request, which is how non-standard-port web apps
    # get found in the first place.
    web_ports = [
        item["port"]
        for item in _port_details(assessment)
        if item["port"] in (80, 443, 8000, 8080, 8088, 8443, 8888, 9090) or item["service"].startswith("HTTP")
    ]
    announce("web", f"scanning {len(web_ports)} web port(s)")
    console.header(
        "Stage 3/5  Web application", f"{len(web_ports)} web port(s)", color=console.enable_color()
    )
    started = time.time()
    web_findings = 0
    for port in web_ports:
        url = f"{guess_url_scheme(port)}://{address}:{port}"
        if port == 443:
            url = f"https://{address}"
        elif guess_url_scheme(port) == "https" and port != 443:
            url = f"https://{address}:{port}"
        try:
            web_report = webscan.scan(
                url, timeout=http_timeout, verify_tls=verify_tls, check_paths=check_paths
            )
            assessment.bundle.add(web_report)
            web_findings += len(web_report.findings)
        except Exception as exc:
            assessment.bundle.add(_error_report("webscan", url, exc))
    assessment.record("web", "ok", time.time() - started, f"{len(web_ports)} URL(s) assessed", web_findings)

    # --- stage 4: TLS ----------------------------------------------------
    tls_ports = [p for p in assessment.open_ports if p in (443, 8443, 993, 995, 4443)]
    announce("tls", f"auditing {len(tls_ports)} TLS endpoint(s)")
    console.header(
        "Stage 4/5  TLS configuration", f"{len(tls_ports)} endpoint(s)", color=console.enable_color()
    )
    started = time.time()
    tls_findings = 0
    for port in tls_ports or ([443] if 443 in assessment.open_ports else []):
        try:
            tls_report = tls_audit.audit(
                address, port, sni=target if not target.replace(".", "").isdigit() else None
            )
            assessment.bundle.add(tls_report)
            tls_findings += len(tls_report.findings)
        except Exception as exc:
            assessment.bundle.add(_error_report("tls_audit", f"{address}:{port}", exc))
    assessment.record(
        "tls", "ok", time.time() - started, f"{len(tls_ports)} endpoint(s) audited", tls_findings
    )

    # --- stage 5: prioritise ---------------------------------------------
    announce("prioritise", "building attack-surface summary")
    console.header("Stage 5/5  Attack surface summary", "risk-ranked", color=console.enable_color())
    started = time.time()
    assessment.attack_surface = build_attack_surface(assessment)
    _print_attack_surface(assessment.attack_surface)
    assessment.record(
        "prioritise",
        "ok",
        time.time() - started,
        f"{len(assessment.attack_surface)} service(s) ranked",
    )

    assessment.bundle.add(assessment.report())
    return assessment


def _group_services(recon: Report) -> dict[str, list[int]]:
    grouped: dict[str, list[int]] = {}
    for entry in recon.data.get("ports", []):
        if entry["state"] != "open":
            continue
        grouped.setdefault(entry["service"], []).append(entry["port"])
    return grouped


def _error_report(module: str, target: str, exc: Exception) -> Report:
    report = Report(module=module, target=target)
    report.add(
        check=f"{module}.error",
        title=f"{module} stage failed",
        severity="info",
        detail=f"{type(exc).__name__}: {exc}",
        remediation="Re-run this stage alone for a focused error, and confirm the service is still up.",
    )
    return report


def build_attack_surface(assessment: Assessment) -> list[dict]:
    """Score every open service for how attractive it is as a first step."""
    surface: list[dict] = []

    for entry in _port_details(assessment):
        service = entry["service"]
        port = entry["port"]
        reasons: list[str] = []
        score = 0

        if service in ("Telnet", "rlogin", "FTP"):
            score += 4
            reasons.append("cleartext remote access")
        if service in ("Redis", "MongoDB", "Elasticsearch", "rpcbind", "NFS", "SMB"):
            score += 4
            reasons.append("frequently unauthenticated by default")
        if service in ("HTTP", "HTTPS", "HTTP-alt", "HTTP-proxy", "HTTP-alt"):
            score += 3
            reasons.append("web application reachable")
        if service in CREDENTIAL_SERVICES:
            score += 2
            reasons.append("accepts credentials")
        if entry.get("version"):
            score += 2
            reasons.append(f"exact version disclosed ({entry.get('product') or service} {entry['version']})")
        if entry.get("tls"):
            score -= 1
            reasons.append("traffic is encrypted")

        from ..config import ANONYMOUS_SERVICES

        anonymous = service in ANONYMOUS_SERVICES
        if anonymous:
            reasons.append("anonymous access likely")

        surface.append(
            {
                "port": port,
                "service": service,
                "version": entry.get("version") or "-",
                "product": entry.get("product") or "-",
                "priority": max(1, min(10, score)),
                "anonymous": anonymous,
                "credential_exposed": service in ("Telnet", "FTP", "HTTP", "HTTP-alt", "HTTP-proxy"),
                "reasons": reasons or ["reachable service"],
            }
        )

    return sorted(surface, key=lambda item: -item["priority"])


def _port_details(assessment: Assessment) -> list[dict]:
    for report in assessment.bundle.reports:
        if report.module == "scanner":
            return [entry for entry in report.data.get("ports", []) if entry["state"] == "open"]
    return []


def _print_attack_surface(surface: list[dict]) -> None:
    color = console.enable_color()
    if not surface:
        console.info("no reachable services to rank", color=color)
        return
    console.emit()
    console.kv("ranked attack surface", "", color=color)
    console.table(
        ["pri", "port", "service", "version", "why it matters"],
        [
            [
                console.paint(
                    str(item["priority"]),
                    "bad" if item["priority"] >= 7 else "high" if item["priority"] >= 5 else "medium",
                    color,
                ),
                item["port"],
                item["service"],
                item["version"],
                ", ".join(item["reasons"][:3]),
            ]
            for item in surface
        ],
        color=color,
    )
    console.emit()
    console.info(
        "Priority is a triage aid from exposure and protocol weakness, not a measured exploit.",
        color=color,
    )


def remediation_queue(bundle: Bundle) -> list[Finding]:
    """All findings across the bundle, most severe first."""
    return sorted(bundle.findings, key=lambda f: severity_rank(f.severity), reverse=True)
