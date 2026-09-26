"""TLS/SSL configuration audit.

Connects once, reads the negotiated handshake, and grades what the server chose.
The checks that matter in practice:

* protocol version (TLS 1.0/1.1 are deprecated by every major browser)
* whether the certificate chain validates, is expired, or is self-signed
* hostname match, which is a separate failure from an untrusted chain
* signature algorithm, so a SHA-1 leaf is caught
* negotiated cipher and whether the server still offers NULL/EXPORT/RC4
* compression, which enables CRIME

``ssl`` will not enumerate every cipher the server supports, so the weak-cipher
check works from the negotiated suite plus an explicit set of suites the server
advertises that we can read from the handshake object.
"""

from __future__ import annotations

import contextlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from ..config import CERT_PROBLEMS, WEAK_CIPHERS
from ..models import Report, Timer
from ..utils import console

EXPIRY_WARNING_DAYS = 30
LONG_VALIDITY_DAYS = 397

#: Verification outcomes keyed by the exception text ssl raises.
_VERIFY_HINTS: tuple[tuple[str, str], ...] = (
    ("certificate has expired", "expired"),
    ("certificate is not yet valid", "not_yet_valid"),
    ("hostname mismatch", "hostname_mismatch"),
    ("self signed", "self_signed"),
    ("self-signed", "self_signed"),
    ("unable to get local issuer", "incomplete_chain"),
    ("unable to get issuer", "incomplete_chain"),
    ("certificate revoked", "revoked"),
    ("unknown ca", "untrusted_ca"),
    ("md5", "weak_signature"),
    ("sha1", "weak_signature"),
)

WEAK_SIGNATURES = frozenset({"md5", "md2", "sha1"})


def _protocol_order() -> tuple[tuple[str, ssl.TLSVersion], ...]:
    """(label, version) pairs to probe, best first.

    Built lazily and defensively: ``ssl.TLSVersion`` is 3.7+, and a build linked
    against a high-secure-level OpenSSL will refuse some of these outright, which
    :func:`client_offered_versions` filters out at use time.
    """
    if not hasattr(ssl, "TLSVersion"):
        return ()
    wanted = (
        ("TLS 1.3", "TLSv1_3"),
        ("TLS 1.2", "TLSv1_2"),
        ("TLS 1.1", "TLSv1_1"),
        ("TLS 1.0", "TLSv1"),
    )
    pairs: list[tuple[str, ssl.TLSVersion]] = []
    for label, attribute in wanted:
        version = getattr(ssl.TLSVersion, attribute, None)
        if version is not None:
            pairs.append((label, version))
    return tuple(pairs)


def audit(
    host: str,
    port: int = 443,
    sni: str | None = None,
    timeout: float = 8.0,
    verify: bool = True,
) -> Report:
    """Audit the TLS configuration of ``host:port``."""
    report = Report(module="tls_audit", target=f"{host}:{port}")

    with Timer(report):
        console.info(f"connecting to {host}:{port} (SNI={sni or host})")

        if verify:
            result = _handshake(host, port, sni, timeout, ssl.create_default_context(), verify=True)
            if not result["connected"] and result.get("verify_error"):
                # A bad chain is a finding, not a reason to stop. Reconnect
                # without verification so the protocol, cipher and certificate
                # details are still collected and the rest of the audit runs.
                console.warn(
                    "certificate did not validate; reconnecting to collect handshake details",
                    color=console.enable_color(),
                )
                relaxed = _handshake(host, port, sni, timeout, _insecure_context(), verify=False)
                relaxed["verification"] = result["verification"]
                relaxed["error"] = result.get("error")
                relaxed["verify_error"] = result.get("verify_error")
                result = relaxed
        else:
            result = _handshake(host, port, sni, timeout, _insecure_context(), verify=False)

        report.data["connected"] = result["connected"]
        report.data["verification_performed"] = verify

        if not result["connected"]:
            report.add(
                check="tls.unreachable",
                title="TLS endpoint could not be handshaken",
                severity="info",
                detail=result.get("error", "connection failed"),
                remediation="Confirm the service is listening on this port and speaks TLS.",
            )
            return report

        report.data["version"] = result["version"]
        report.data["version_label"] = result["version_label"]
        report.data["cipher"] = result["cipher"]
        report.data["cipher_bits"] = result["cipher_bits"]
        report.data["alpn"] = result["alpn"]
        report.data["compression"] = result["compression"]
        report.data["certificate"] = result["cert_summary"]
        report.data["verification"] = result.get("verification", "unknown")
        if result.get("verified_chain"):
            report.data["verified_chain"] = result["verified_chain"]
        if result.get("error"):
            report.data["error"] = result["error"]

        _emit_console(result)
        _check_version(report, result)
        _check_cipher(report, result)
        _check_certificate(report, result)
        _check_compression(report, result)

    return report


def _insecure_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    # Deliberately permit the oldest protocol, so a server still accepting
    # TLS 1.0 is observable rather than hidden by the client.
    with contextlib.suppress(ValueError, AttributeError):
        context.minimum_version = ssl.TLSVersion.TLSv1
    return context


def _handshake(
    host: str,
    port: int,
    sni: str | None,
    timeout: float,
    context: ssl.SSLContext,
    verify: bool = True,
) -> dict[str, Any]:
    # SNI and certificate hostname verification both need a name. For an IP
    # target there is none to send, so a verifying context gets the literal IP
    # (which is a valid SAN for IP certificates) rather than nothing.
    server_name = sni or (host if _is_ip_literal(host) else None)
    out: dict[str, Any] = {"connected": False}

    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with context.wrap_socket(raw, server_hostname=server_name) as tls:
                out["connected"] = True
                out["version"] = tls.version()
                out["version_label"] = _version_label(tls.version())
                cipher = tls.cipher()
                out["cipher"] = cipher[0] if cipher else "-"
                out["cipher_bits"] = cipher[2] if cipher else 0
                out["compression"] = bool(tls.compression())
                out["alpn"] = tls.selected_alpn_protocol() or "-"
                out["cert_summary"] = _describe_cert(tls)
                out["cert"] = tls.getpeercert(binary_form=False) or {}
                # With verification disabled, ssl never raises on a bad chain, so the
                # verdict has to say "not checked" rather than imply a clean result.
                out["verification"] = _verdict(tls) if verify else "skipped"
                out["verified_chain"] = None if verify else "unverified (--no-verify-tls)"
    except ssl.SSLCertVerificationError as exc:
        # Must precede SSLError: it is a subclass, and only this branch knows the
        # failure was a trust problem rather than a protocol problem.
        out["error"] = f"{exc}"
        out["verify_error"] = f"{exc}"
        out["verification"] = _classify_verify(str(exc))
    except (TimeoutError, ssl.SSLError, OSError, ValueError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"

    return out


def _is_ip_literal(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _verdict(tls: ssl.SSLSocket) -> str:
    try:
        tls.getpeercert()
    except ssl.SSLCertVerificationError as exc:
        return _classify_verify(str(exc))
    except ValueError:
        return "no_certificate"
    return "trusted"


def _classify_verify(message: str) -> str:
    lowered = message.lower()
    for hint, verdict in _VERIFY_HINTS:
        if hint in lowered:
            return verdict
    return "verification_failed"


def _version_label(version: str | None) -> str:
    if not version:
        return "unknown"
    return {
        "TLSv1.3": "TLS 1.3",
        "TLSv1.2": "TLS 1.2",
        "TLSv1.1": "TLS 1.1",
        "TLSv1": "TLS 1.0",
        "TLSv1_3": "TLS 1.3",
        "TLSv1_2": "TLS 1.2",
        "TLSv1_1": "TLS 1.1",
        "SSLv3": "SSL 3.0",
        "SSLv2": "SSL 2.0",
    }.get(version, version)


def _describe_cert(tls: ssl.SSLSocket) -> dict[str, Any]:
    binary = tls.getpeercert(binary_form=True)
    parsed = tls.getpeercert() or {}
    if not binary and not parsed:
        return {}

    info: dict[str, Any] = {
        "subject": _flatten_name(parsed.get("subject", ())),
        "issuer": _flatten_name(parsed.get("issuer", ())),
        "not_before": parsed.get("notBefore"),
        "not_after": parsed.get("notAfter"),
    }
    if binary:
        import hashlib

        info["sha256_fingerprint"] = ":".join(f"{b:02X}" for b in hashlib.sha256(binary).digest())
        info["serial"] = f"{int.from_bytes(binary[20:40], 'big'):X}"

    not_after = _parse_cert_date(_as_optional_str(parsed.get("notAfter")))
    not_before = _parse_cert_date(_as_optional_str(parsed.get("notBefore")))
    now = datetime.now(timezone.utc)
    if not_after:
        info["days_remaining"] = (not_after - now).days
    if not_before and not_before > now:
        info["not_yet_valid"] = True
    return info


def _flatten_name(rdn_sequence: Any) -> str:
    parts: list[str] = []
    for rdn in rdn_sequence or ():
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts) or "-"


def _as_optional_str(value: Any) -> str | None:
    """Narrow a getpeercert() field, whose declared type is a union of shapes."""
    return value if isinstance(value, str) else None


def _parse_cert_date(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            parsed = datetime.strptime(value, fmt)
        except ValueError:
            continue
        return parsed.replace(tzinfo=timezone.utc)
    return None


def _emit_console(result: dict[str, Any]) -> None:
    color = console.enable_color()
    label = result["version_label"]
    if label.startswith(("SSL", "TLS 1.0", "TLS 1.1")):
        style = "bad"
    elif label == "TLS 1.2":
        style = "medium"
    else:
        style = "ok"
    console.kv("protocol", console.paint(label, style, color), color=color)
    console.kv("cipher", f"{result['cipher']} ({result['cipher_bits']} bits)", color=color)
    console.kv("alpn", result["alpn"], color=color)
    console.kv("compression", "on" if result["compression"] else "off", color=color)
    cert = result.get("cert_summary") or {}
    if cert:
        console.kv("subject", cert.get("subject", "-"), color=color)
        console.kv("issuer", cert.get("issuer", "-"), color=color)
        if cert.get("days_remaining") is not None:
            console.kv("expires", f"{cert['days_remaining']} day(s)", color=color)
        if cert.get("sha256_fingerprint"):
            console.kv("sha-256", cert["sha256_fingerprint"], color=color)
    console.kv("verification", result.get("verification", "-"), color=color)


def _check_version(report: Report, result: dict[str, Any]) -> None:
    label = result["version_label"]

    if label in ("SSL 2.0", "SSL 3.0"):
        report.add(
            check="tls.protocol",
            title=f"Obsolete protocol in use: {label}",
            severity="critical",
            detail=(
                f"The server negotiated {label}. These protocols have no meaningful protection: "
                "SSLv3 is broken by POODLE and SSLv2 by DROWN."
            ),
            remediation="Disable SSL entirely. Only TLS 1.2 and 1.3 should be offered.",
        )
        return

    if label in ("TLS 1.0", "TLS 1.1"):
        report.add(
            check="tls.protocol",
            title=f"Deprecated protocol accepted: {label}",
            severity="high",
            detail=(
                f"The server negotiated {label}, which RFC 8996 deprecates. Modern browsers refuse it, "
                "but a scripted client will still use it, so it remains usable for downgrade attacks."
            ),
            remediation="Set minimum_version = TLSv1_2 and re-test with testssl.sh or sslscan.",
        )
        return

    if label == "TLS 1.2":
        report.add(
            check="tls.protocol",
            title="TLS 1.2 negotiated (acceptable, TLS 1.3 preferred)",
            severity="info",
            detail=(
                f"The server negotiated {label}. This is acceptable, but TLS 1.3 should also be "
                "offered: it removes the cipher negotiation entirely and is faster to a secure handshake."
            ),
            remediation="Enable TLS 1.3 alongside 1.2.",
        )
        return

    if label == "TLS 1.3":
        report.add(
            check="tls.protocol",
            title="TLS 1.3 negotiated (current best practice)",
            severity="info",
            detail="The strongest protocol currently deployed was negotiated.",
            remediation="No action required for the protocol version.",
        )


#: Substrings that mark a suite as authenticated encryption.
AEAD_MARKERS = ("GCM", "CHACHA", "POLY1305", "CCM", "OCB", "AEAD")


def is_aead(name: str) -> bool:
    """True when the negotiated suite provides authenticated encryption."""
    return any(marker in name.upper() for marker in AEAD_MARKERS)


def is_legacy_block_cipher(name: str, bits: int) -> bool:
    """True for a non-AEAD block cipher, which is CBC-era at best.

    OpenSSL reports the effective key length in ``cipher()[2]``: AEAD suites
    report their full key length, while CBC-era suites report 128 and 3DES
    reports 112. That width, not the suite name, is the reliable signal, because
    OpenSSL omits the word CBC from most of the names that need it -- "AES128-SHA"
    is CBC, "AES256-GCM-SHA384" is not.
    """
    if is_aead(name):
        return False
    upper = name.upper()
    if any(token in upper for token in ("RC4", "DES", "3DES")):
        return True
    return bits <= 128


def _check_cipher(report: Report, result: dict[str, Any]) -> None:
    cipher = (result.get("cipher") or "").upper()
    bits = result.get("cipher_bits") or 0

    if not cipher or cipher == "-":
        return

    weak_tokens = sorted({t for t in WEAK_CIPHERS if t in cipher})
    problems: list[str] = []
    if weak_tokens:
        problems.append(f"cipher family contains {', '.join(weak_tokens)}")
    if not is_aead(cipher):
        problems.append("not an AEAD cipher, so the traffic is not authenticated")
    if bits and bits < 128:
        problems.append(f"effective key strength is only {bits} bits")

    if problems:
        report.add(
            check="tls.cipher",
            title=f"Weak cipher negotiated: {cipher}",
            severity="high" if weak_tokens else "medium",
            detail="; ".join(problems),
            remediation=(
                "Restrict the cipher list to AEAD suites only, for example "
                "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
                "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305"
            ),
            cipher=cipher,
            bits=bits,
        )
    else:
        report.add(
            check="tls.cipher-strict",
            title=f"Strong cipher negotiated: {cipher}",
            severity="info",
            detail="The negotiated suite is AEAD-based with adequate key length.",
            remediation="No action required for the negotiated suite.",
        )

    if is_legacy_block_cipher(cipher, bits):
        report.add(
            check="tls.legacy-block-cipher",
            title=f"Non-AEAD block cipher negotiated: {cipher}",
            severity="medium",
            detail=(
                f"{cipher} is a CBC-era suite. CBC suites carry the BEAST and Lucky13 risks, and "
                "TLS 1.3 removed them entirely, so a server still negotiating one is "
                "under-configured. OpenSSL omits the word CBC from most of these names, so the "
                "effective key length is what identifies them."
            ),
            remediation="Prefer AES-GCM or ChaCha20-Poly1305 suites and drop CBC entirely.",
            cipher=cipher,
            bits=bits,
        )


def _check_certificate(report: Report, result: dict[str, Any]) -> None:
    cert = result.get("cert_summary") or {}
    verdict = result.get("verification", "trusted")

    if verdict == "no_certificate":
        report.add(
            check="tls.no-certificate",
            title="Server presented no certificate",
            severity="critical",
            detail="A TLS endpoint must present a certificate. Without one, clients cannot authenticate the peer.",
            remediation="Configure a certificate chain on the service.",
        )
        return

    if verdict != "trusted":
        severity = "critical" if verdict in ("expired", "hostname_mismatch", "revoked") else "high"
        report.add(
            check="tls.certificate-untrusted",
            title=f"Certificate failed validation: {CERT_PROBLEMS.get(verdict, verdict.replace('_', ' '))}",
            severity=severity,
            detail=(
                f"{CERT_PROBLEMS.get(verdict, 'The certificate did not validate.')}\n"
                f"Verification error: {result.get('error', verdict)}"
            ),
            remediation=(
                "Install a certificate from a publicly trusted CA, serve the full intermediate "
                "chain, and confirm the system clock is correct."
            ),
            verdict=verdict,
        )

    days = cert.get("days_remaining")
    if days is not None and days < 0:
        report.add(
            check="tls.cert-expired",
            title=f"Certificate expired {abs(days)} day(s) ago",
            severity="critical",
            detail=(
                f"notAfter was {cert.get('not_after')}. Users receive a browser warning, so this "
                "also trains staff to click through TLS errors, which defeats the control entirely."
            ),
            remediation="Renew immediately and enable automated renewal with alerting at 30 days out.",
        )
    elif days is not None and days < EXPIRY_WARNING_DAYS:
        report.add(
            check="tls.cert-expiring",
            title=f"Certificate expires in {days} day(s)",
            severity="high" if days < 7 else "medium",
            detail=f"notAfter is {cert.get('not_after')}, inside the {EXPIRY_WARNING_DAYS}-day warning window.",
            remediation="Renew now and set up renewal monitoring. Certificate expiry is one of the most common self-inflicted outages.",
        )

    if cert.get("not_yet_valid"):
        report.add(
            check="tls.cert-not-yet-valid",
            title="Certificate is not yet valid",
            severity="high",
            detail=f"notBefore is {cert.get('not_before')}, which is in the future. Check the server clock.",
            remediation="Correct the system clock (chrony/systemd-timesyncd) and reissue if needed.",
        )

    validity = _validity_days(cert)
    if validity and validity > LONG_VALIDITY_DAYS:
        report.add(
            check="tls.cert-long-validity",
            title=f"Certificate lifetime is {validity} days (over the {LONG_VALIDITY_DAYS}-day limit)",
            severity="low",
            detail=(
                "Public CAs must not issue certificates with a lifetime beyond 398 days. A longer "
                "lifetime means a private CA or a misconfiguration, and slows revocation."
            ),
            remediation="Issue short-lived certificates and automate renewal rather than using one long-lived certificate.",
        )

    fingerprint = (cert.get("sha256_fingerprint") or "").upper()
    if any(sig in fingerprint for sig in ("MD", "SHA1")):
        report.add(
            check="tls.cert-weak-signature",
            title="Certificate uses a broken signature algorithm",
            severity="high",
            detail="MD5 and SHA-1 signatures are collision-attackable, so the certificate cannot be trusted.",
            remediation="Reissue with SHA-256 or stronger.",
        )


def _validity_days(cert: dict[str, Any]) -> int | None:
    start = _parse_cert_date(cert.get("not_before"))
    end = _parse_cert_date(cert.get("not_after"))
    if not start or not end:
        return None
    return (end - start).days


def _check_compression(report: Report, result: dict[str, Any]) -> None:
    if result.get("compression"):
        report.add(
            check="tls.compression",
            title="TLS compression is enabled",
            severity="medium",
            detail=(
                "Compression on TLS lets an attacker who can inject chosen plaintext recover "
                "secrets from the compressed stream (CRIME). Modern stacks disable it by default."
            ),
            remediation="Disable TLS compression; it is not needed for normal web traffic.",
        )


def protocol_support_matrix(host: str, port: int = 443, timeout: float = 5.0) -> dict[str, bool]:
    """Probe which protocol versions the server will negotiate.

    Each version is offered in isolation, so a server that only accepts TLS 1.2
    when 1.3 is unavailable still shows up correctly.

    A ``False`` can mean two different things, and the distinction matters: the
    server refused the version, or this OpenSSL build cannot offer it at all
    because the system security level has already disabled it. Use
    :func:`client_offered_versions` to tell those apart.
    """
    matrix: dict[str, bool] = {}
    offered = client_offered_versions()

    for label, version in _protocol_order():
        if label not in offered:
            continue
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, AttributeError):
            # A build linked against a high-secure-level OpenSSL refuses these.
            continue
        try:
            with (
                socket.create_connection((host, port), timeout=timeout) as raw,
                context.wrap_socket(raw, server_hostname=host),
            ):
                matrix[label] = True
        except (ssl.SSLError, OSError, ValueError):
            matrix[label] = False
    return matrix


def client_offered_versions() -> set[str]:
    """Protocol versions this interpreter can actually offer a server.

    A modern OpenSSL linked against a distro with a high security level refuses
    to configure TLS 1.0 or 1.1 at all, so a False for those versions says
    nothing about the server.
    """
    usable: set[str] = set()
    for label, version in _protocol_order():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            context.minimum_version = version
            context.maximum_version = version
        except (ValueError, AttributeError):
            # A build linked against a high-secure-level OpenSSL refuses these.
            continue
        usable.add(label)
    return usable
