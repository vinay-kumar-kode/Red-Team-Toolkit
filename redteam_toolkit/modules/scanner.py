"""TCP port scanner with service fingerprinting and banner capture.

Behaviour that matters for a reliable scan:

* Connections run on a bounded thread pool, so a 32-port scan takes one
  timeout instead of 32.
* Every socket is closed via ``with``/``finally``, so a timed-out port cannot
  leak a descriptor and eventually exhaust the process.
* A connection-refused result is reported as ``closed`` and separated from
  ``filtered`` (timeout), which are very different signals during triage.
* Banner reads are length-capped and decoded leniently, because service
  banners are frequently binary or truncated.
"""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..config import (
    ANONYMOUS_SERVICES,
    DEFAULT_TCP_PORTS,
    RISKY_EXPOSURE,
    TCP_SERVICES,
)
from ..models import Report, Timer
from ..utils import console
from ..utils.net import classify, parse_ports

MAX_BANNER = 512
BANNER_PROBES: dict[str, bytes] = {
    "FTP": b"220",
    "SSH": b"SSH-2.0-rtt_probe\r\n",
    "SMTP": b"EHLO rtt.local\r\n",
    "POP3": b"",  # server speaks first
    "IMAP": b"",  # server speaks first
    "MySQL": b"",  # server speaks first
    "SMB": b"",  # binary, no text banner
    "RDP": b"",  # binary
    "VNC": b"",  # server speaks first
    "Redis": b"PING\r\n",
    "Elasticsearch": b"GET / HTTP/1.0\r\n\r\n",
}

#: Soft hints keyed by port for services that never send a usable banner.
PORT_HINTS: dict[int, str] = {
    443: "HTTPS (TLS, banner encrypted)",
    993: "IMAPS (TLS)",
    995: "POP3S (TLS)",
    3306: "MySQL (banner is binary)",
    5432: "PostgreSQL (binary startup packet)",
    27017: "MongoDB (binary wire protocol)",
    1521: "Oracle TNS (binary)",
    1433: "Microsoft SQL Server (TDS)",
    2049: "NFS (no banner by design)",
    111: "rpcbind (no banner by design)",
}


def scan(
    target: str,
    address: str,
    ports: str | list[int] | None = None,
    timeout: float = 1.0,
    workers: int = 64,
    grab_banners: bool = True,
    http_detect: bool = True,
    on_result: Any = None,
) -> Report:
    """Scan ``address`` (already authorized) and return a populated report."""
    report = Report(module="scanner", target=target)

    with Timer(report):
        port_list = parse_ports(ports, DEFAULT_TCP_PORTS)
        console.info(
            f"probing {len(port_list)} port(s) on {address} "
            f"with {min(workers, len(port_list))} worker(s), {timeout:g}s timeout"
        )
        console.info(f"target class: {classify(address)}")
        console.emit()

        with ThreadPoolExecutor(max_workers=max(1, min(workers, len(port_list)))) as pool:
            results = list(
                pool.map(
                    lambda port: probe(address, port, timeout, grab_banners, http_detect),
                    port_list,
                )
            )

    results.sort(key=lambda item: item["port"])
    open_ports = [item["port"] for item in results if item["state"] == "open"]

    report.data["address"] = address
    report.data["scope"] = classify(address)
    report.data["ports_scanned"] = len(port_list)
    report.data["open_ports"] = open_ports
    report.data["closed_ports"] = [i["port"] for i in results if i["state"] == "closed"]
    report.data["filtered_ports"] = [i["port"] for i in results if i["state"] == "filtered"]
    report.data["scan_seconds"] = round(report.duration_seconds, 3)
    report.data["ports"] = results

    if on_result is not None:
        for item in results:
            on_result(item)

    _emit_table(results, open_ports)
    _add_findings(report, results, open_ports)
    return report


def _emit_table(results: list[dict], open_ports: list[int]) -> None:
    color = console.enable_color()
    console.kv("open ports", console.paint(str(len(open_ports)), "bold", color), color=color)
    console.emit()
    console.table(
        ["port", "state", "service", "version", "banner"],
        [
            [
                item["port"],
                console.paint(item["state"], "ok" if item["state"] == "open" else "dim", color),
                item["service"],
                item.get("version") or "-",
                _clip(item.get("banner") or "-"),
            ]
            for item in results
        ],
        color=color,
    )


def _clip(text: str, width: int = 58) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "~"


def probe(
    host: str,
    port: int,
    timeout: float = 1.0,
    grab_banner: bool = True,
    http_detect: bool = True,
) -> dict[str, Any]:
    """Connect to one port and describe it. Never raises."""
    service, should_probe, version_pattern = TCP_SERVICES.get(port, ("unknown", False, ""))
    record: dict[str, Any] = {
        "port": port,
        "state": "filtered",
        "service": service,
        "version": None,
        "banner": None,
        "tls": False,
    }

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            record["state"] = "open"

            if port == 443 or port in (8443, 4443):
                record["tls"] = True

            if not grab_banner:
                pass
            elif should_probe or service in BANNER_PROBES:
                banner = _read_banner(sock, service, port)
                if banner:
                    _apply_banner(record, banner, version_pattern)
            elif service == "unknown":
                _identify_unregistered(sock, record, http_detect)
    except ConnectionRefusedError:
        record["state"] = "closed"
    except TimeoutError:
        record["state"] = "filtered"
    except OSError as exc:
        record["state"] = "error"
        record["banner"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # defensive: a scanner must never abort a sweep
        record["state"] = "error"
        record["banner"] = f"{type(exc).__name__}: {exc}"

    if not record.get("product"):
        hint = PORT_HINTS.get(port)
        if hint and record["state"] == "open":
            record["product"] = hint
    return record


def _apply_banner(record: dict[str, Any], banner: str, version_pattern: str = "") -> None:
    record["banner"] = banner
    record["product"] = _extract_product(banner)
    record["version"] = _extract_version(banner, version_pattern) or _version_from_product(banner)
    if record["service"] == "unknown":
        record["service"] = _service_from_banner(banner) or record["service"]


def _identify_unregistered(sock: socket.socket, record: dict[str, Any], http_detect: bool) -> None:
    """Work out what is on a port that nothing is registered for.

    Two cheap probes, in order. First a short passive read, because SSH, SMTP,
    FTP, IMAP, POP3, MySQL, Redis and VNC all greet before being spoken to, and
    a passive read identifies them without sending anything at all. Only if the
    port is silent does it send a single HTTP HEAD, since a lab web app on an
    odd port is the other common case.
    """
    greeting = _read_greeting(sock)
    if greeting:
        _apply_banner(record, greeting)
        return

    if not http_detect:
        return

    response = _probe_http(sock)
    if not response:
        return
    record["service"] = "HTTP-unknown-port"
    record["banner"] = response
    record["product"] = _extract_product(response)
    # Only the Server/X-Powered-By headers carry a software version. The status
    # line's "HTTP/1.1" is the protocol, and treating that as a version produces
    # bogus CVE matches.
    record["version"] = _extract_version(response, r"(?:Server|X-Powered-By):\s*\S*?(\d+\.\d+(?:\.\d+)?)")


def _read_greeting(sock: socket.socket, wait: float = 0.6) -> str:
    """Read whatever the server volunteers first, without sending anything.

    Uses ``select`` so a silent port costs ``wait`` seconds rather than the full
    socket timeout.
    """
    import select

    try:
        readable, _, _ = select.select([sock], [], [], wait)
        if not readable:
            return ""
        return _recv(sock)
    except (OSError, ValueError):
        return ""


#: Greets that identify a service on a port nothing is registered for.
_GREETING_SERVICES: tuple[tuple[str, str], ...] = (
    (r"^SSH-2\.0", "SSH"),
    (r"^220[- ].*(?:FTP|vsftpd|ProFTPD)", "FTP"),
    (r"^220[- ].*(?:SMTP|Postfix|sendmail|Exim)", "SMTP"),
    (r"^[+-]OK", "IMAP"),
    (r"^\+OK", "POP3"),
    (r"[\d.]+[- ]NULL|\x00\x00\x00\x00.{10}", "MySQL"),
    (r"^-PONG|redis|ERR unknown command", "Redis"),
    (r"RFB \d{3}\.\d{3}", "VNC"),
    (r"^HTTP/", "HTTP"),
    (r'"\d{3} \d{3} \d{3}', "SMB"),
)


def _service_from_banner(banner: str) -> str | None:
    for pattern, service in _GREETING_SERVICES:
        if re.search(pattern, banner):
            return service
    return None


def _probe_http(sock: socket.socket) -> str:
    """Send one HEAD request and return the status line plus Server header."""
    request = (
        b"HEAD / HTTP/1.0\r\n"
        b"Host: probe\r\n"
        b"User-Agent: RedTeamToolkit/2.0\r\n"
        b"Accept: */*\r\n"
        b"Connection: close\r\n\r\n"
    )
    try:
        sock.sendall(request)
        chunks: list[bytes] = []
        total = 0
        while total < 1024:
            chunk = sock.recv(256)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if b"\r\n\r\n" in b"".join(chunks):
                break
    except (TimeoutError, OSError):
        return ""

    raw = b"".join(chunks).decode("utf-8", "replace")
    if not raw.startswith("HTTP/"):
        return ""
    head, _, _body = raw.partition("\r\n\r\n")
    lines = [line for line in head.splitlines() if line]
    interesting = [
        line for line in lines if line.lower().startswith(("server:", "x-powered-by:", "location:"))
    ]
    return " | ".join(lines[:1] + interesting)[:200]


def _read_banner(sock: socket.socket, service: str, port: int) -> str:
    """Read a banner, upgrading to TLS where the port implies it."""
    try:
        if service == "HTTPS" or port in (8443, 4443):
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname="rtt-probe") as tls:
                return _recv(tls)

        probe_bytes = BANNER_PROBES.get(service)
        if probe_bytes:
            sock.sendall(probe_bytes)
        return _recv(sock)
    except (ssl.SSLError, OSError):
        return ""


def _recv(sock: socket.socket) -> str:
    chunks: list[bytes] = []
    try:
        while sum(len(c) for c in chunks) < MAX_BANNER:
            chunk = sock.recv(256)
            if not chunk:
                break
            chunks.append(chunk)
            if service_speaks_first(b"".join(chunks).decode("utf-8", "replace")):
                break
    except (TimeoutError, OSError):
        pass
    return b"".join(chunks).decode("utf-8", "replace").strip()


def service_speaks_first(text: str) -> bool:
    """True once the accumulated text looks like a complete greeting."""
    return text.count("\n") >= 1 and len(text) > 8


def _extract_version(banner: str, pattern: str) -> str | None:
    if not pattern:
        return None
    match = re.search(pattern, banner)
    return match.group(1) if match else None


#: Ordered most specific first. The generic ``SSH-x.y-<impl>`` rule would
#: otherwise swallow ``OpenSSH_8.9p1`` whole, because ``\w`` includes digits and
#: underscores, so a later specific rule would never get a turn.
_PRODUCT_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"OpenSSH[_ -](?P<version>\d+\.\d+(?:p\d+)?)", "product"),
    (r"(?P<product>OpenSSH)[\w.\-]*", "product"),
    (r"(?P<product>vsftpd)\s*(?P<version>[\d.]+)?", "product"),
    (r"(?P<product>ProFTPD)[\w.\-]*", "product"),
    (r"(?P<product>vsftpd)[\d.]*", "product"),
    (r"(?P<product>MySQL)\s*(?P<version>[\d.]+)?", "product"),
    (r"(?P<product>MariaDB)[\w.\-]*", "product"),
    (r"(?P<product>PostgreSQL)[\w.\-]*", "product"),
    (r"(?P<product>redis)[\s-]?(?P<version>[\d.]+)?", "product"),
    (r"(?P<product>Microsoft-IIS)[\w./]*", "server"),
    (r"(?P<product>Microsoft Windows Server \d{4})", "product"),
    (r"(?P<product>Debian)[\w\s]*", "product"),
    (r"(?P<product>Ubuntu)[\w\s]*", "product"),
    (r"(?P<product>CentOS)[\w\s]*", "product"),
    (r"(?P<product>RFB) (?P<version>[\d.]+)", "product"),
    (r"(?P<product>LiteSpeed)[\d.]*", "server"),
    (r"(?P<product>nginx)[\d./]*", "server"),
    (r"(?P<product>Apache)[\d./]*", "server"),
    (r"Server:\s*(?P<product>[^\r\n]+)", "server"),
    (r"SSH-[\d.]+-(?P<product>[A-Za-z][\w.-]*)", "product"),
)


def _extract_product(banner: str) -> str | None:
    for pattern, _kind in _PRODUCT_PATTERNS:
        match = re.search(pattern, banner)
        if not match:
            continue
        groups = match.groupdict()
        # A rule that only captures a version is still a useful match, but it
        # cannot name a product, so it is skipped here rather than raising.
        if not groups.get("product"):
            continue
        return groups["product"].strip()
    return None


def _version_from_product(banner: str) -> str | None:
    """Pull a version out of whichever product rule matched.

    Preferred over a per-port regex because the same product can appear on many
    ports, and a per-port regex has to be rewritten for every service.
    """
    for pattern, _kind in _PRODUCT_PATTERNS:
        match = re.search(pattern, banner)
        if match and match.groupdict().get("version"):
            return match.group("version")
    return None


def _add_findings(report: Report, results: list[dict], open_ports: list[int]) -> None:
    by_service: dict[str, list[dict]] = {}
    for item in results:
        if item["state"] == "open":
            by_service.setdefault(item["service"], []).append(item)

    for service, items in sorted(by_service.items()):
        ports = ", ".join(str(i["port"]) for i in items)
        advice = RISKY_EXPOSURE.get(service)

        if advice:
            report.add(
                check="net.risky-service",
                title=f"{service} exposed on port {ports}",
                severity="high",
                detail=(
                    f"{service} is reachable from the scanning host. {advice} "
                    "Exposed legacy services are the most common initial access path in "
                    "intrusion sets because they are frequently unpatched and unauthenticated."
                ),
                remediation=(
                    "Remove the service if unused, or restrict it to a management VPN / "
                    "fixed bastion address in the host and perimeter firewall."
                ),
                service=service,
                ports=ports,
            )

        if service in ANONYMOUS_SERVICES:
            report.add(
                check="net.anonymous-service",
                title=f"{service} commonly permits anonymous access",
                severity="high",
                detail=(
                    f"{service} on port {ports} is a protocol that historically allows "
                    "anonymous or unauthenticated access by default. If it is not explicitly "
                    "restricted, the content is effectively public."
                ),
                remediation=(
                    "Require authentication, disable guest/anonymous access, and confirm with "
                    "an unauthenticated client that the service now rejects the request."
                ),
                service=service,
                ports=ports,
            )

        for item in items:
            if item.get("product") and item.get("version"):
                report.add(
                    check="net.version-disclosure",
                    title=f"{item['service']} discloses exact version ({item['product']} {item['version']})",
                    severity="medium",
                    detail=(
                        f"The banner on port {item['port']} identifies the running software as "
                        f"'{item['product']} {item['version']}'. An exact version lets an "
                        "attacker skip discovery and go straight to known vulnerabilities."
                    ),
                    remediation=(
                        "Suppress the banner where the protocol allows it, or patch to a "
                        "current release and verify with the vendor's CVE feed."
                    ),
                    port=item["port"],
                    banner=item.get("banner"),
                )

    http_discovered = [
        item for item in results if item["service"] == "HTTP-unknown-port" and item["state"] == "open"
    ]
    if http_discovered:
        ports = ", ".join(str(item["port"]) for item in http_discovered)
        report.add(
            check="net.web-on-unlisted-port",
            title=f"HTTP service on unlisted port(s): {ports}",
            severity="low",
            detail=(
                f"A HEAD request on port(s) {ports} returned an HTTP response, but the port is "
                "not a standard web port. Services on non-standard ports are easy to miss during "
                "a review, and they are a common place for an admin panel or a forgotten staging "
                "deployment to live."
            ),
            remediation=(
                "Confirm each service is intended, and check it against the same review as any "
                "other web application."
            ),
            ports=ports,
        )

    if not open_ports:
        report.add(
            check="net.no-open-ports",
            title="No open ports found in the scanned range",
            severity="info",
            detail=(
                "Every probed port was refused or filtered. If this host is expected to be "
                "reachable, the perimeter firewall is dropping traffic, which is a valid "
                "control but hides the real service count from internal tooling."
            ),
            remediation="Confirm the intended exposure with the asset owner before treating this as complete.",
        )

    filtered = report.data["filtered_ports"]
    if filtered and open_ports:
        report.add(
            check="net.filtered-ports",
            title=f"{len(filtered)} port(s) silently dropped by a firewall",
            severity="info",
            detail=(
                f"Ports {', '.join(str(p) for p in filtered[:20])} timed out rather than "
                "being refused. Dropped packets usually mean a stateful firewall is in front "
                "of the host, which slows enumeration and also hides real services."
            ),
            remediation="Audit the perimeter ruleset so intentional drops are documented.",
        )
