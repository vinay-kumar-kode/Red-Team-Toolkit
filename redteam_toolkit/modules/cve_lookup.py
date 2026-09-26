"""Offline CVE lookup for versions discovered by the scanner.

The bundled database in ``data/cve_db.json`` is a curated subset covering the
software that turns up most often in a lab or a small server estate. It exists
so a version string discovered by a banner grab can be turned into a
prioritised patch list without any network access.

Two honesty rules are baked in, because a tool that overstates its own
confidence is worse than one that says nothing:

1. Every match is a *candidate*. Affected ranges are recorded to a minor version
   and may be wrong, so the report always says to confirm against the vendor
   advisory and NVD.
2. A product that is not in the database returns "unknown", never "no
   vulnerabilities". Absence from a small database is not evidence of absence.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from ..config import CVE_DB_PATH
from ..models import Report, Timer
from ..utils import console

SEVERITY_ORDER = ("critical", "high", "medium", "low")

#: ``2.4.29``, ``1.8.0-1ubuntu2``, ``8.0.1p1``, ``5.3.29`` all reduce to a
#: comparable tuple of the leading numeric components.
_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


def parse_version(value: str) -> tuple[int, ...]:
    """Extract a comparable numeric version tuple from a banner version string.

    Trailing non-numeric parts are dropped, so distro suffixes and OpenSSH's
    ``p1`` portability marker do not defeat the comparison. An unparseable
    version returns an empty tuple, which never matches a range.
    """
    if not value:
        return ()
    match = _VERSION_RE.search(value)
    if not match:
        return ()
    return tuple(int(part) for part in match.group(1).split("."))


def _pad(left: tuple[int, ...], width: int) -> tuple[int, ...]:
    return left + (0,) * max(0, width - len(left))


def version_in_range(version: str, start: str, end: str) -> bool:
    """True when ``version`` falls within the inclusive ``start``..``end`` range."""
    parsed = parse_version(version)
    low = parse_version(start)
    high = parse_version(end)
    if not parsed or not low or not high:
        return False
    width = max(len(parsed), len(low), len(high))
    parsed, low, high = _pad(parsed, width), _pad(low, width), _pad(high, width)
    return low <= parsed <= high


@dataclass(slots=True)
class Match:
    """One CVE considered applicable to a detected product and version."""

    cve_id: str
    product: str
    severity: str
    cvss: float
    summary: str
    remediation: str
    affected: str
    version_found: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve_id,
            "product": self.product,
            "severity": self.severity,
            "cvss": self.cvss,
            "affected_range": self.affected,
            "detected_version": self.version_found,
            "summary": self.summary,
            "remediation": self.remediation,
        }


@lru_cache(maxsize=4)
def load_database(path: str | None = None) -> dict[str, Any]:
    """Load and cache the CVE database."""
    db_path = Path(path or CVE_DB_PATH)
    if not db_path.is_file():
        return {"products": {}, "version": "-", "updated": "-", "error": f"{db_path} not found"}

    try:
        data: dict[str, Any] = json.loads(db_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"products": {}, "version": "-", "updated": "-", "error": str(exc)}
    return data


def normalise_product(name: str) -> str:
    """Reduce a banner product string to a lookup key.

    ``Apache/2.4.29 (Ubuntu)`` -> ``apache http server``,
    ``OpenSSH_8.9p1`` -> ``openssh``.
    """
    lowered = (name or "").strip().lower()
    if not lowered:
        return ""

    if lowered.startswith("apache/") or lowered.startswith("apache ") or lowered == "apache2":
        return "apache http server"
    if "openbsd ssh" in lowered or "openssh" in lowered or lowered.startswith("ssh-"):
        return "openssh"
    if "vsftpd" in lowered:
        return "vsftpd"
    if "proftpd" in lowered:
        return "proftpd"
    if lowered.startswith("nginx"):
        return "nginx"
    if lowered.startswith("php") or "mod_php" in lowered:
        return "php"
    if "tomcat" in lowered:
        return "apache tomcat"
    if "log4j" in lowered:
        return "log4j"
    if "redis" in lowered:
        return "redis"
    if "solr" in lowered:
        return "apache solr"
    if "elasticsearch" in lowered:
        return "elasticsearch"
    if "samba" in lowered or lowered.startswith("smb"):
        return "samba"
    if "openssl" in lowered or "libssl" in lowered:
        return "openssl"
    if "libcurl" in lowered or lowered.startswith("curl/"):
        return "curl"
    if "jenkins" in lowered:
        return "jenkins"
    if "exim" in lowered:
        return "exim"
    if "jquery" in lowered:
        return "jquery"
    if "spring" in lowered:
        return "spring framework"
    if "windows" in lowered and ("server" in lowered or "7" in lowered):
        return "windows smb"
    return lowered


def lookup(product: str, version: str, db: dict[str, Any] | None = None) -> list[Match]:
    """Return every CVE in the database whose range contains ``version``."""
    database = db if db is not None else load_database()
    products = database.get("products", {})
    key = normalise_product(product)

    entry = products.get(key)
    if entry is None:
        entry = _by_alias(products, key)

    if entry is None:
        return []

    matches: list[Match] = []
    for cve in entry.get("cves", []):
        for pair in cve.get("affected", []):
            if len(pair) != 2:
                continue
            start, end = pair
            if version_in_range(version, start, end):
                matches.append(
                    Match(
                        cve_id=cve["id"],
                        product=key,
                        severity=cve.get("severity", "medium"),
                        cvss=float(cve.get("cvss", 0.0)),
                        summary=cve.get("summary", ""),
                        remediation=cve.get("remediation", ""),
                        affected=f"{start} - {end}",
                        version_found=version,
                    )
                )
                break  # one match per CVE even with several ranges

    return sorted(matches, key=lambda m: -m.cvss)


def _by_alias(products: dict[str, Any], key: str) -> dict[str, Any] | None:
    """Find a product by one of its declared aliases."""
    for entry in products.values():
        if not isinstance(entry, dict):
            continue
        aliases = entry.get("aliases") or []
        if key in [alias.lower() for alias in aliases if isinstance(alias, str)]:
            return entry
    return None


def lookup_many(
    observations: Sequence[tuple[str, str]], db: dict[str, Any] | None = None
) -> dict[str, list[Match]]:
    """Look up many ``(product, version)`` pairs at once."""
    database = db if db is not None else load_database()
    out: dict[str, list[Match]] = {}
    for product, version in observations:
        if not version or version == "-":
            continue
        matches = lookup(product, version, database)
        if matches:
            out[f"{product} {version}"] = matches
    return out


# --- report ---------------------------------------------------------------


def lookup_report(
    observations: Sequence[tuple[str, str]],
    source: str = "(scan results)",
    db_path: str | None = None,
) -> Report:
    """Build a CVE report from a list of ``(product, version)`` observations."""
    report = Report(module="cve_lookup", target=source)
    database = load_database(db_path)

    with Timer(report):
        if database.get("error"):
            report.add(
                check="cve.db-missing",
                title="CVE database could not be loaded",
                severity="low",
                detail=str(database["error"]),
                remediation="Run from the project root, or pass --db with a valid path to the database.",
            )
            report.data["db_error"] = database["error"]
            return report

        report.data["db_version"] = database.get("version", "-")
        report.data["db_updated"] = database.get("updated", "-")
        report.data["products_in_db"] = len(database.get("products", {}))
        report.data["cves_in_db"] = sum(
            len(entry.get("cves", [])) for entry in database.get("products", {}).values()
        )
        report.data["disclaimer"] = database.get("disclaimer", "")

        results = lookup_many(observations, database)
        report.data["observations"] = [f"{p} {v}" for p, v in observations]
        report.data["matched_products"] = sorted(results)
        report.data["match_count"] = sum(len(v) for v in results.values())
        report.data["matches"] = {key: [m.to_dict() for m in matches] for key, matches in results.items()}

        _emit_console(results, database)

        _add_coverage_finding(report, observations, database)

        all_matches = [m for matches in results.values() for m in matches]
        if not all_matches:
            report.add(
                check="cve.no-matches",
                title="No known CVEs matched the detected versions",
                severity="info",
                detail=(
                    f"Checked {len(observations)} product/version pair(s) against "
                    f"{report.data['cves_in_db']} CVEs covering "
                    f"{report.data['products_in_db']} products. Nothing fell inside a recorded "
                    "affected range. This is not proof the software is vulnerability free: the "
                    "bundled database is a small curated subset and does not cover every product "
                    "or every branch."
                ),
                remediation=(
                    "Confirm against NVD and the vendor advisory for the exact build, including "
                    "the distribution's backported patches, which a version string alone will not show."
                ),
            )
            return report

        for observation_key, matches in results.items():
            worst = max(matches, key=lambda m: m.cvss)
            report.add(
                check="cve.version-vulnerable",
                title=f"{observation_key} matches {len(matches)} known CVE(s), worst is {worst.cve_id} (CVSS {worst.cvss})",
                severity=worst.severity,
                detail=(
                    "; ".join(
                        f"{m.cve_id} (CVSS {m.cvss}, affects {m.affected}): {m.summary}" for m in matches[:4]
                    )
                    + ". Affected range matched: "
                    + "; ".join(f"{m.cve_id} covers {m.affected}" for m in matches[:4])
                    + "."
                ),
                remediation="; ".join(dict.fromkeys(m.remediation for m in matches if m.remediation)),
                product=worst.product,
                version=observation_key.split()[-1],
                cves=[m.cve_id for m in matches],
                max_cvss=worst.cvss,
            )

    return report


def _add_coverage_finding(
    report: Report, observations: Sequence[tuple[str, str]], database: dict[str, Any]
) -> None:
    """State which detected products the database cannot speak about.

    A product that is absent produces no match, and no match is indistinguishable
    from a patched version unless this is said out loud.
    """
    products = database.get("products", {})
    uncovered = [
        f"{product} {version}"
        for product, version in observations
        if version
        and version != "-"
        and normalise_product(product) not in products
        and _by_alias(products, normalise_product(product)) is None
    ]
    if not uncovered:
        return

    report.add(
        check="cve.uncovered-product",
        title=f"{len(uncovered)} detected product(s) are not in the database",
        severity="info",
        detail=(
            "Not covered: "
            + ", ".join(uncovered[:12])
            + f". The database holds {len(products)} products. Anything outside it returns no "
            "result at all, so silence here carries no information either way."
        ),
        remediation=(
            "Check these products against NVD and the vendor's own security advisories. An "
            "uncovered product is an unknown, not a clean bill of health."
        ),
        uncovered=uncovered[:20],
    )


def _emit_console(results: dict[str, list[Match]], database: dict[str, Any]) -> None:
    color = console.enable_color()
    console.kv(
        "database",
        f"v{database.get('version', '-')} updated {database.get('updated', '-')}, "
        f"{sum(len(e.get('cves', [])) for e in database.get('products', {}).values())} CVEs",
        color=color,
    )

    if not results:
        console.kv("matches", "0", color=color)
        return

    rows: list[list[Any]] = []
    for observation, matches in results.items():
        for match in matches:
            rows.append(
                [
                    match.cve_id,
                    console.paint(match.severity, match.severity, color),
                    f"{match.cvss}",
                    match.affected,
                    observation,
                ]
            )
    rows.sort(key=lambda row: -float(row[2]))
    console.kv("matches", str(sum(len(v) for v in results.values())), color=color)
    print()
    console.table(["cve", "severity", "cvss", "affected range", "detected"], rows, color=color)


def from_scan_report(scan_report: Report) -> list[tuple[str, str]]:
    """Extract ``(product, version)`` pairs from a scanner report's data."""
    observations: list[tuple[str, str]] = []
    for entry in scan_report.data.get("ports", []):
        if entry.get("state") != "open":
            continue
        version = entry.get("version")
        product = entry.get("product")
        if version:
            observations.append((product or entry.get("service", "unknown"), version))
        elif product and product not in ("HTTPS (TLS, banner encrypted)",):
            observations.append((entry.get("service", "unknown"), ""))
    return observations


def products_in_db(db_path: str | None = None) -> Iterable[str]:
    database = load_database(db_path)
    return sorted(database.get("products", {}))
