"""HTTP/HTTPS configuration scanner.

All requests are read-only ``GET``/``HEAD``/``OPTIONS``. The scanner reports
missing headers, leaky banners, weak cookies, risky HTTP methods and a short
list of accidentally-published files. It does not attempt exploitation: the
"reflected input" check only reports *whether* the marker string came back, and
flags it for manual verification, because deciding exploitability is a
judgement call this tool should not make on its own.
"""

from __future__ import annotations

import re
import ssl
from concurrent.futures import ThreadPoolExecutor
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.exceptions import RequestException, SSLError

from ..config import COOKIE_ATTRS, HEADER_BASELINE, LEAKY_HEADERS
from ..models import Report, Timer
from ..utils import console
from ..utils.net import guess_url_scheme

USER_AGENT = "RedTeamToolkit/2.0 (+educational security assessment)"
DEFAULT_TIMEOUT = 10.0

#: Read-only paths that are commonly published by accident. Presence alone is
#: the finding; the scanner never writes, uploads or follows what it finds.
SENSITIVE_PATHS: tuple[tuple[str, str, str], ...] = (
    ("/.env", "critical", "Environment file is downloadable; it usually holds database and API credentials."),
    ("/.git/config", "critical", "Git metadata is exposed, disclosing repository structure and remotes."),
    ("/.git/HEAD", "high", "Git metadata is exposed, disclosing the checked-out ref."),
    ("/.svn/entries", "high", "Subversion metadata is exposed."),
    ("/.hg/requires", "high", "Mercurial metadata is exposed."),
    ("/.DS_Store", "low", "macOS directory listing index is downloadable."),
    ("/backup.zip", "medium", "Backup archive is publicly downloadable and may contain source and secrets."),
    ("/phpinfo.php", "high", "phpinfo() discloses the full PHP configuration including paths and modules."),
    ("/server-status", "medium", "Apache server-status is enabled, exposing request and process details."),
    ("/server-info", "medium", "Apache server-info is enabled, exposing the full configuration."),
    (
        "/wp-login.php",
        "info",
        "WordPress login page is reachable, which is normal but is a brute-force target.",
    ),
    (
        "/phpmyadmin/",
        "medium",
        "phpMyAdmin is reachable; it is a high-value takeover target when unauthenticated.",
    ),
    ("/admin", "info", "An admin path is reachable."),
    (
        "/actuator/env",
        "high",
        "Spring Boot actuator exposes environment variables, commonly including secrets.",
    ),
    ("/actuator/health", "info", "Spring Boot health endpoint is reachable."),
    ("/.well-known/security.txt", "info", "security.txt is published."),
    ("/robots.txt", "info", "robots.txt is published."),
    ("/sitemap.xml", "info", "sitemap.xml is published."),
)

#: Methods worth asking about. TRACE reflects the request, which enables
#: cross-site tracing when a cross-origin browser request reaches it.
PROBE_METHODS = ("OPTIONS", "TRACE")

CVE_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"Apache/(\d+\.\d+\.\d+)", "Apache HTTP Server"),
    (r"nginx/(\d+\.\d+\.\d+)", "nginx"),
    (r"Microsoft-IIS/(\d+\.\d+)", "Microsoft IIS"),
    (r"OpenSSL/(\d+\.\d+\.\w+)", "OpenSSL"),
    (r"Drupal/(\d+\.\d+)", "Drupal"),
    (r"Joomla[/ ](\d+\.\d+)", "Joomla"),
    (r"PHP/(\d+\.\d+\.\d+)", "PHP"),
    (r"Express", "Express"),
    (r"JetBrains", "JetBrains products"),
)


def scan(
    url: str,
    timeout: float = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
    follow_redirects: bool = True,
    check_paths: bool = True,
    check_methods: bool = True,
    reflect_check: bool = False,
    workers: int = 8,
    on_finding: Any = None,
) -> Report:
    """Scan a web target and return a populated report."""
    if not url.startswith(("http://", "https://")):
        port = urlparse("//" + url).port
        url = f"{guess_url_scheme(port or 80)}://{url}"

    report = Report(module="webscan", target=url)
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    session.max_redirects = 5

    with Timer(report):
        console.info(f"requesting {url} (timeout {timeout:g}s, TLS verify={verify_tls})")

        try:
            response = session.get(
                url, timeout=timeout, verify=verify_tls, allow_redirects=follow_redirects, stream=False
            )
        except SSLError as exc:
            return _ssl_failure(report, url, exc)
        except RequestException as exc:
            report.add(
                check="web.unreachable",
                title="Target could not be reached",
                severity="info",
                detail=f"{type(exc).__name__}: {exc}",
                remediation="Confirm the host resolves, the port is correct, and the service is listening.",
            )
            report.data["reachable"] = False
            report.data["error"] = f"{type(exc).__name__}: {exc}"
            return report

        report.data["reachable"] = True
        report.data["final_url"] = response.url
        report.data["status"] = response.status_code
        report.data["redirected"] = response.url != url
        report.data["redirect_chain"] = [f"{h.status_code} {h.url}" for h in response.history]
        report.data["content_type"] = response.headers.get("Content-Type", "-")
        report.data["content_length"] = len(response.content)
        report.data["server"] = response.headers.get("Server", "-")
        report.data["elapsed_seconds"] = round(response.elapsed.total_seconds(), 3)
        report.data["tls_verified"] = bool(verify_tls)

        _emit_console(response, report)

        _check_status(response, report)
        _check_security_headers(response, report)
        _check_leaky_headers(response, report)
        _check_cookies(response, report)
        _check_https(url, response, report)
        _check_csp(response, report)
        _check_software(response, report, on_finding)

        if check_methods:
            _check_methods(session, response, timeout, verify_tls, report)
        if reflect_check:
            _check_reflection(session, url, timeout, verify_tls, report)
        if check_paths:
            _check_paths(session, url, timeout, verify_tls, workers, report, on_finding)

    return report


def _ssl_failure(report: Report, url: str, exc: Exception) -> Report:
    message = str(exc)
    report.data["reachable"] = False
    report.data["tls_error"] = message
    severity = "high" if "certificate" in message.lower() else "info"
    report.add(
        check="web.tls-handshake",
        title="TLS handshake or certificate validation failed",
        severity=severity,
        detail=message,
        remediation=(
            "Renew the certificate with a full chain, and confirm the system clock and "
            "intermediate bundle. Browsers will show the same error to users."
            if severity == "high"
            else "Confirm the service is listening on this port and speaks TLS."
        ),
    )
    console.error(f"TLS failure: {message}")
    return report


def _emit_console(response: requests.Response, report: Report) -> None:
    color = console.enable_color()
    console.kv("status", console.paint(str(response.status_code), "bold", color), color=color)
    console.kv("final url", response.url, color=color)
    if response.history:
        chain = " -> ".join(f"{h.status_code}" for h in response.history)
        console.kv("redirects", f"{len(response.history)} hop(s): {chain}", color=color)
    console.kv("content-type", response.headers.get("Content-Type", "-"), color=color)
    console.kv("server", response.headers.get("Server", "-"), color=color)
    console.emit()


def _check_status(response: requests.Response, report: Report) -> None:
    status = response.status_code
    if status in (401, 403):
        report.add(
            check="web.auth-required",
            title=f"Root path returns {status} (authentication enforced)",
            severity="info",
            detail=(
                f"The server answered {status}, so a login sits in front of the application. "
                "This is good practice; confirm the login itself is rate limited."
            ),
            remediation="Add lockout and alerting on repeated failures, and require MFA.",
        )
    elif status == 200:
        pass
    elif status >= 500:
        report.add(
            check="web.server-error",
            title=f"Server error {status}",
            severity="medium",
            detail="The application failed to handle a normal request, which may leak stack traces in the body.",
            remediation="Check the response body for a stack trace and fix the underlying exception.",
        )
    elif 300 <= status < 400:
        report.add(
            check="web.weak-redirect",
            title=f"Unfollowed redirect ({status})",
            severity="low",
            detail="The base URL redirects. Following it is normal, but the target matters for header checks.",
            remediation="Re-run with redirects followed so headers are read from the final page.",
        )
    elif status == 404:
        report.add(
            check="web.not-found",
            title="Base path returns 404",
            severity="info",
            detail="No content at the requested path. Point the scan at a real application path.",
            remediation="Verify the URL and re-run.",
        )


def _check_security_headers(response: requests.Response, report: Report) -> None:
    present = {k.lower() for k in response.headers}
    missing: list[str] = []
    for header, (why, severity) in HEADER_BASELINE.items():
        if header.lower() in present:
            report.data.setdefault("headers_present", []).append(header)
        else:
            missing.append(header)
            report.add(
                check="web.header-missing",
                title=f"Missing security header: {header}",
                severity=severity,
                detail=why,
                remediation=f"Add `Content-Security-Policy`-style configuration emitting {header} on every response.",
                header=header,
            )
    report.data["headers_present"] = sorted(set(report.data.get("headers_present", [])))
    report.data["headers_missing"] = missing


def _check_leaky_headers(response: requests.Response, report: Report) -> None:
    lowered = {k.lower(): v for k, v in response.headers.items()}
    for header, why in LEAKY_HEADERS.items():
        value = lowered.get(header.lower())
        if value:
            report.add(
                check="web.header-disclosure",
                title=f"Technology disclosure header: {header}",
                severity="medium",
                detail=f"{header}: {value}. {why}",
                remediation="Remove or blank the header at the web server or framework configuration level.",
                header=header,
                value=value,
            )


def _check_cookies(response: requests.Response, report: Report) -> None:
    cookies = response.raw.headers.get_all("Set-Cookie") if hasattr(response.raw, "headers") else []
    if not cookies:
        return
    report.data["cookies_set"] = len(cookies)
    issues: set[str] = set()
    names: list[str] = []

    for raw in cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        names.append(name)
        attrs = {p.split("=", 1)[0].strip().lower() for p in parts[1:] if p}
        for required in COOKIE_ATTRS:
            if required.lower() not in attrs:
                issues.add(required)

    report.data["cookie_names"] = names
    if not issues:
        report.add(
            check="web.cookie-attributes-ok",
            title="Session cookies carry Secure, HttpOnly and SameSite",
            severity="info",
            detail=f"{len(cookies)} cookie(s) set ({', '.join(names[:6])}), all with protective attributes.",
            remediation="No action. Re-check whenever a new cookie is introduced.",
        )
        return

    report.add(
        check="web.cookie-attributes",
        title=f"Cookies are missing attributes: {', '.join(sorted(issues))}",
        severity="high" if "HttpOnly" in issues else "medium",
        detail=(
            f"{len(cookies)} cookie(s) set ({', '.join(names[:6])}). Missing attributes mean: "
            + "; ".join(COOKIE_ATTRS[i] for i in sorted(issues) if i in COOKIE_ATTRS)
        ),
        remediation="Set Secure, HttpOnly and SameSite=Lax (or Strict) on every session cookie.",
        missing=sorted(issues),
    )


def _check_https(url: str, response: requests.Response, report: Report) -> None:
    if url.startswith("https://"):
        return
    report.add(
        check="web.no-https",
        title="Target is served over plain HTTP",
        severity="high",
        detail=(
            "The URL scheme is http, so session cookies and credentials travel in cleartext "
            "and can be read or modified by anything on the path."
        ),
        remediation="Redirect all HTTP to HTTPS, then enable HSTS so browsers stop trying HTTP at all.",
    )


def _check_csp(response: requests.Response, report: Report) -> None:
    csp = response.headers.get("Content-Security-Policy", "")
    if not csp:
        return
    report.data["csp"] = csp

    directives = _parse_csp(csp)
    # script-src falls back to default-src when it is absent.
    script_src = directives.get("script-src") or directives.get("default-src")
    scope = "script-src" if "script-src" in directives else "default-src (as script-src fallback)"

    weaknesses: list[str] = []
    if script_src is None:
        weaknesses.append(f"neither script-src nor default-src is set ({csp[:80]})")
    else:
        tokens = script_src.split()
        if "*" in tokens:
            weaknesses.append(f"{scope} allows any origin (*), which defeats the purpose of a CSP")
        if "'unsafe-inline'" in tokens:
            weaknesses.append("'unsafe-inline' lets any injected <script> run")
        if "'unsafe-eval'" in tokens:
            weaknesses.append("'unsafe-eval' permits eval() and weakens CSP substantially")
        if "data:" in tokens:
            weaknesses.append(f"{scope} permits data: URIs, a known bypass for base64 payloads")
        # A source is recognised by prefix, because a nonce and a hash are spelled
        # "'nonce-<value>'" and "'sha256-<base64>'". "'none'" blocks all script
        # outright and is the strictest option available, not a weakness.
        usable = any(t in ("'self'", "'strict-dynamic'") or t.startswith("https:") for t in tokens) or any(
            t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in tokens
        )
        if not usable and not any(t == "'none'" for t in tokens) and "script-src" in directives:
            weaknesses.append(
                f"{scope} names no usable source, so the policy is either blocking all script "
                "or, where a browser falls back, allowing it"
            )

    if weaknesses:
        report.add(
            check="web.csp-weak",
            title="Content-Security-Policy is present but weak",
            severity="medium",
            detail="; ".join(weaknesses),
            remediation="Replace wildcard and unsafe-* sources with explicit origins or per-request nonces.",
            csp=csp,
        )
    else:
        report.add(
            check="web.csp-strict",
            title="Content-Security-Policy looks strict",
            severity="info",
            detail=f"No wildcards or unsafe-* found in {scope}: {csp[:160]}",
            remediation="Keep it under test; a CSP rots as new features are added.",
        )


def _parse_csp(csp: str) -> dict[str, str]:
    directives: dict[str, str] = {}
    for part in csp.split(";"):
        name, _, value = part.strip().partition(" ")
        if name:
            directives[name.lower()] = value.strip()
    return directives


def _check_software(response: requests.Response, report: Report, on_finding: Any = None) -> None:
    haystack = " ".join(f"{k}: {v}" for k, v in response.headers.items()) + " " + response.text[:4096]

    found: list[dict] = []
    for pattern, product in CVE_PATTERNS:
        match = re.search(pattern, haystack, re.IGNORECASE)
        if match:
            version = match.group(1) if match.groups() else "-"
            found.append({"product": product, "version": version})
            report.add(
                check="web.version-disclosure",
                title=f"{product} version disclosed ({version})",
                severity="medium",
                detail=(
                    f"The response advertises {product} {version}. Version disclosure converts "
                    "reconnaissance into exploit selection, because every published CVE now has "
                    "a known-good target."
                ),
                remediation="Suppress version strings at the edge, then confirm the installed version is patched.",
                product=product,
                version=version,
            )
            if on_finding is not None:
                on_finding(product, version)
    report.data["software_detected"] = found


def _check_methods(
    session: requests.Session,
    response: requests.Response,
    timeout: float,
    verify_tls: bool,
    report: Report,
) -> None:
    results: dict[str, Any] = {}
    for method in PROBE_METHODS:
        try:
            probe = session.request(
                method, response.url, timeout=timeout, verify=verify_tls, allow_redirects=False
            )
            results[method] = probe.status_code
        except RequestException as exc:
            results[method] = f"error: {type(exc).__name__}"

    report.data["methods"] = results
    allowed = response.headers.get("Allow", "")

    if results.get("TRACE") == 200:
        report.add(
            check="web.trace-enabled",
            title="HTTP TRACE method is enabled",
            severity="medium",
            detail=(
                "TRACE reflects the full request back, including headers a cross-origin "
                "script can set. Historically this enabled cross-site tracing and it remains "
                "an unnecessary attack surface."
            ),
            remediation="Disable TRACE in the web server configuration (Apache: TraceEnable off).",
        )
    if "PUT" in allowed or "DELETE" in allowed or "PROPFIND" in allowed:
        report.add(
            check="web.write-methods",
            title=f"Write-capable methods advertised: {allowed}",
            severity="medium",
            detail=f"Allow header lists '{allowed}'. Unauthenticated write access is a data-integrity risk.",
            remediation="Restrict methods per route and require authentication for anything that writes.",
            allow=allowed,
        )


def _check_reflection(
    session: requests.Session,
    url: str,
    timeout: float,
    verify_tls: bool,
    report: Report,
) -> None:
    """Report whether a harmless alphanumeric marker is reflected.

    This is a detection aid, not an exploit. If the marker comes back, the value
    needs manual review for output-encoding before drawing any conclusion.
    """
    marker = "rttmarker9x2q"
    probe_url = url if "?" in url else f"{url}?q={marker}"
    if "?" in url:
        probe_url = url + f"&q={marker}"

    try:
        probe = session.get(probe_url, timeout=timeout, verify=verify_tls)
    except RequestException as exc:
        report.add(
            check="web.reflect-error",
            title="Reflection check could not run",
            severity="info",
            detail=f"{type(exc).__name__}: {exc}",
            remediation="Confirm the URL accepts a query parameter and re-run.",
        )
        return

    body = probe.text
    count = body.count(marker)
    report.data["reflection"] = {"marker_occurrences": count, "probe_url": probe_url}

    if count:
        context = _context_around(body, marker)
        report.add(
            check="web.reflected-input",
            title=f"Query parameter value is reflected {count}x in the response",
            severity="medium",
            detail=(
                f"The marker appears {count} time(s) in the response body. Reflection without "
                f"output encoding is the precondition for reflected XSS. Context: {context[:120]!r}. "
                "Confirm manually whether the surrounding context is HTML, an attribute, or a "
                "script block before treating this as exploitable."
            ),
            remediation="Encode output for its context on the server. Never rely on client-side escaping.",
            occurrences=count,
        )
    else:
        report.add(
            check="web.no-reflection",
            title="Query parameter value is not reflected",
            severity="info",
            detail="The marker did not appear in the response body, which rules out naive reflected XSS here.",
            remediation="No action; reflection-based payloads are not reaching this page.",
        )


def _context_around(body: str, marker: str, span: int = 40) -> str:
    index = body.find(marker)
    if index == -1:
        return ""
    return " ".join(body[max(0, index - span) : index + len(marker) + span].split())


def _check_paths(
    session: requests.Session,
    url: str,
    timeout: float,
    verify_tls: bool,
    workers: int,
    report: Report,
    on_finding: Any = None,
) -> None:
    base = url if url.endswith("/") else url + "/"
    results: list[dict] = []

    def probe(entry: tuple[str, str, str]) -> dict:
        path, severity, why = entry
        target = urljoin(base, path.lstrip("/"))
        try:
            response = session.get(target, timeout=timeout, verify=verify_tls, allow_redirects=True)
            return {
                "path": path,
                "url": target,
                "status": response.status_code,
                "severity": severity,
                "why": why,
                "size": len(response.content),
                "note": why,
            }
        except RequestException as exc:
            return {
                "path": path,
                "url": target,
                "status": "error",
                "severity": severity,
                "why": why,
                "size": 0,
                "note": f"{type(exc).__name__}",
            }

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(SENSITIVE_PATHS)))) as pool:
        results = list(pool.map(probe, SENSITIVE_PATHS))

    published: list[dict] = []
    for item in results:
        status = item["status"]
        if (
            isinstance(status, int)
            and 200 <= status < 300
            and item["path"]
            not in (
                "/robots.txt",
                "/sitemap.xml",
                "/.well-known/security.txt",
                "/admin",
                "/wp-login.php",
                "/actuator/health",
            )
        ):
            published.append(item)
            report.add(
                check="web.exposed-path",
                title=f"Sensitive path is publicly served: {item['path']}",
                severity=item["severity"],
                detail=f"{item['why']} The server answered {status} with {item['size']} bytes.",
                remediation="Block the path at the web server or reverse proxy, and rotate any secret that was exposed.",
                path=item["path"],
                status=status,
                url=item["url"],
            )
            if on_finding is not None:
                on_finding(item)

    report.data["path_checks"] = results
    report.data["exposed_paths"] = [item["path"] for item in published]
    report.data["paths_probed"] = len(results)


def tls_context(verify: bool) -> ssl.SSLContext:
    """SSL context for the scanner, verifying or not."""
    if verify:
        return ssl.create_default_context()
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context
