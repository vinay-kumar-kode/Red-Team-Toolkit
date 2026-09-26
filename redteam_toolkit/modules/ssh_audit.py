"""SSH server configuration and posture audit.

Two modes:

* **Config mode** (offline): parse an ``sshd_config``, or any file plus its
  ``Include`` globs, and grade the settings. This is the mode that produces
  actionable findings and it needs no network access.
* **Live mode**: connect to a port, read the version banner, and compare the
  offered key-exchange, cipher, MAC and host-key algorithms against a baseline.
  A passive banner read plus the negotiated proposal is enough to find the
  common misconfigurations without attempting authentication.

Note on default resolution: sshd applies the *first* value it sees for a
keyword, so this module records both the file value and the compiled-in
default, and flags the settings where the default is the weak one.
"""

from __future__ import annotations

import base64
import re
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import SSH_WEAK_SETTINGS
from ..models import Report, Timer
from ..utils import console

DEFAULT_TIMEOUT = 8.0

#: Compiled-in OpenSSH defaults, for the settings where the default is the risk.
SSHD_DEFAULTS: dict[str, str] = {
    "PermitRootLogin": "prohibit-password",
    "PasswordAuthentication": "yes",
    "PubkeyAuthentication": "yes",
    "PermitEmptyPasswords": "no",
    "MaxAuthTries": "6",
    "X11Forwarding": "no",
    "LoginGraceTime": "120",
    "ClientAliveInterval": "0",
    "MaxSessions": "10",
    "AllowTcpForwarding": "yes",
    "Protocol": "2",
    "LogLevel": "INFO",
}

TRUTHY = frozenset({"yes", "true", "on", "1", "all", "any"})
FALSY = frozenset({"no", "false", "off", "0", "none"})

#: Key exchange algorithms that should no longer be offered.
WEAK_KEX = frozenset(
    {
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group-exchange-sha1",
        "diffie-hellman-group14-sha1",
        "rsa1024-sha1",
    }
)
WEAK_CIPHERS = frozenset(
    {
        "arcfour",
        "arcfour128",
        "arcfour256",
        "3des-cbc",
        "des-cbc",
        "blowfish-cbc",
        "aes128-cbc",
        "aes192-cbc",
        "aes256-cbc",
        "cast128-cbc",
        "rc2-cbc",
        "rc4",
    }
)
WEAK_MACS = frozenset(
    {
        "hmac-md5",
        "hmac-md5-96",
        "hmac-sha1",
        "hmac-sha1-96",
        "umac-64@openssh.com",
    }
)
WEAK_HOST_KEYS = frozenset({"ssh-dss", "ssh-rsa"})

STRONG_KEX = (
    "sntrup761x25519-sha512@openssh.com",
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
)
STRONG_CIPHERS = (
    "chacha20-poly1305@openssh.com",
    "aes256-gcm@openssh.com",
    "aes128-gcm@openssh.com",
    "aes256-ctr",
    "aes128-ctr",
)
STRONG_MACS = ("hmac-sha2-512", "hmac-sha2-256")
STRONG_HOST_KEYS = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-512",
    "rsa-sha2-256",
)

_BANNER_PROBE = b"SSH-2.0-RedTeamToolkit_probe\r\n"


@dataclass(slots=True)
class Directive:
    """One parsed sshd_config directive."""

    keyword: str
    value: str
    source_file: str
    line_no: int
    context: str = ""  # e.g. "Match User bob"

    @property
    def location(self) -> str:
        return f"{self.source_file}:{self.line_no}"


@dataclass(slots=True)
class ParsedConfig:
    directives: list[Directive] = field(default_factory=list)
    files: list[str] = field(default_factory=list)
    include_failures: list[str] = field(default_factory=list)

    def effective(self, keyword: str) -> Directive | None:
        """First value for a keyword, which is what sshd itself uses."""
        for directive in self.directives:
            if directive.keyword == keyword:
                return directive
        return None

    def all_for(self, keyword: str) -> list[Directive]:
        return [d for d in self.directives if d.keyword == keyword]


# --- config parsing -------------------------------------------------------


def parse_config(path: str | Path, follow_includes: bool = True, _depth: int = 0) -> ParsedConfig:
    """Parse an sshd_config, resolving Include directives relative to its directory."""
    parsed = ParsedConfig()
    config_path = Path(path)
    if not config_path.is_file():
        return parsed

    parsed.files.append(str(config_path))
    base_dir = config_path.parent
    context = ""

    try:
        text = config_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        parsed.include_failures.append(f"{config_path}: {exc}")
        return parsed

    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split(None, 1)
        keyword = parts[0]
        value = parts[1].strip() if len(parts) > 1 else ""

        lowered = keyword.lower()

        if lowered == "include":
            if follow_includes and _depth < 5:
                for pattern in value.split():
                    for candidate in sorted(base_dir.glob(pattern)):
                        nested = parse_config(candidate, follow_includes=True, _depth=_depth + 1)
                        parsed.directives.extend(nested.directives)
                        parsed.files.extend(nested.files)
                        parsed.include_failures.extend(nested.include_failures)
            continue

        if lowered == "match":
            context = line
            parsed.directives.append(Directive("Match", value, str(config_path), line_no, context))
            continue

        canonical = _canonical(keyword)
        parsed.directives.append(Directive(canonical, value, str(config_path), line_no, context))

    return parsed


def _canonical(keyword: str) -> str:
    """Map a directive keyword to its canonical spelling.

    The original casing is preserved for keywords that are not in the known
    table, so ``Compression`` and ``compression`` both match later lookups.
    """
    lowered = keyword.lower()
    for known in SSHD_DEFAULTS:
        if known.lower() == lowered:
            return known
    return keyword


def _snake(keyword: str) -> str:
    """``PermitRootLogin`` -> ``permit-root-login``, for check identifiers.

    Splitting only on lower-to-upper transitions keeps a run of capitals as one
    word, so ``MACs`` becomes ``macs`` rather than ``ma-cs``.
    """
    return "-".join(re.findall(r"[A-Za-z0-9]+", re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "-", keyword))).lower()


# --- config analysis ------------------------------------------------------


def audit_config(path: str | Path, follow_includes: bool = True) -> Report:
    """Audit an sshd_config offline."""
    config_path = Path(path)
    report = Report(module="ssh_audit", target=str(config_path))

    with Timer(report):
        if not config_path.is_file():
            report.add(
                check="ssh.config-missing",
                title="sshd_config not found",
                severity="low",
                detail=f"{config_path} does not exist or is not readable.",
                remediation="Pass --config /etc/ssh/sshd_config, or copy it off the host first.",
            )
            return report

        parsed = parse_config(config_path, follow_includes=follow_includes)
        report.data["config"] = str(config_path)
        report.data["files_parsed"] = parsed.files
        report.data["include_failures"] = parsed.include_failures
        report.data["directives"] = len(parsed.directives)
        report.data["match_blocks"] = len(parsed.all_for("Match"))

        _emit_config_console(parsed)

        for failure in parsed.include_failures:
            report.add(
                check="ssh.include-unreadable",
                title="An included configuration file could not be read",
                severity="low",
                detail=failure,
                remediation="Read every file in the Include glob, or a hardened setting may be silently missed.",
            )

        _check_settings(report, parsed)
        _check_algorithms(report, parsed)
        _check_presence(report, parsed)
        _check_compression(report, parsed)

    return report


def _emit_config_console(parsed: ParsedConfig) -> None:
    color = console.enable_color()
    console.kv("files parsed", str(len(parsed.files)), color=color)
    for name in parsed.files:
        console.kv("  ", name, color=color)
    console.kv("directives", str(len(parsed.directives)), color=color)
    console.kv("match blocks", str(len(parsed.all_for("Match"))), color=color)
    console.emit()
    interesting = [
        d
        for d in parsed.directives
        if d.keyword in SSH_WEAK_SETTINGS
        or d.keyword
        in ("Compression", "Protocol", "LogLevel", "MaxSessions", "AllowTcpForwarding", "Banner", "HostKey")
    ]
    if interesting:
        console.kv("security-relevant settings", "", color=color)
        console.table(
            ["setting", "value", "source", "in Match"],
            [
                [d.keyword, d.value or "(empty)", Path(d.source_file).name, "yes" if d.context else "-"]
                for d in interesting[:25]
            ],
            color=color,
        )


def _check_settings(report: Report, parsed: ParsedConfig) -> None:
    for keyword, (why, severity) in SSH_WEAK_SETTINGS.items():
        directive = parsed.effective(keyword)
        default = SSHD_DEFAULTS.get(keyword, "")

        if directive is None:
            # Not set: the compiled-in default applies, and that default is the risk.
            if _default_is_weak(keyword, default):
                report.add(
                    check=f"ssh.{_snake(keyword)}",
                    title=f"{keyword} is not set, so the default '{default}' applies",
                    severity=severity,
                    detail=f"{why} The setting is absent, so sshd falls back to '{default}'.",
                    remediation=f"Set {keyword} explicitly. Relying on a default is how these settings drift.",
                    keyword=keyword,
                    value=f"(default) {default}",
                )
            continue

        value = directive.value.strip()
        lowered = value.lower()

        if keyword == "PermitRootLogin" and lowered in ("yes", "true", "1"):
            report.add(
                check=f"ssh.{_snake(keyword)}",
                title="Direct root SSH login is permitted",
                severity="critical",
                detail=(
                    "PermitRootLogin yes exposes the most privileged account to automated password "
                    "guessing. Root is also the account every attacker tries first, and a root "
                    "shell skips horizontal-movement steps entirely."
                ),
                remediation="Set PermitRootLogin no and administer through a named sudoer account with a key.",
                location=directive.location,
            )
        elif keyword == "PermitEmptyPasswords" and lowered in TRUTHY:
            report.add(
                check=f"ssh.{_snake(keyword)}",
                title="Accounts with blank passwords may log in",
                severity="critical",
                detail=(
                    "PermitEmptyPasswords yes allows any account with an empty shadow entry to be "
                    "authenticated. A single unconfigured service account becomes an entry point."
                ),
                remediation="Set PermitEmptyPasswords no and audit /etc/shadow for empty password fields.",
                location=directive.location,
            )
        elif keyword == "PasswordAuthentication" and lowered in TRUTHY:
            report.add(
                check=f"ssh.{_snake(keyword)}",
                title="SSH password authentication is enabled",
                severity="high",
                detail=(
                    "Passwords are guessable over the network, so every exposed SSH port is a "
                    "brute-force target. With no lockout, an attacker gets unlimited attempts."
                ),
                remediation="Set PasswordAuthentication no, require keys, and use fail2ban as a stopgap until keys are deployed.",
                location=directive.location,
            )
        elif keyword == "PubkeyAuthentication" and lowered in FALSY:
            report.add(
                check=f"ssh.{_snake(keyword)}",
                title="Public key authentication is disabled",
                severity="high",
                detail="With keys disabled, password authentication is the only option available.",
                remediation="Set PubkeyAuthentication yes so key-based login is possible.",
                location=directive.location,
            )
        elif keyword == "MaxAuthTries":
            if value.isdigit() and int(value) > 6:
                report.add(
                    check="ssh.max-auth-tries",
                    title=f"MaxAuthTries is {value} (default 6)",
                    severity="low",
                    detail=(
                        f"Each additional try multiplies how many passwords a single connection can "
                        f"test, so {value} attempts per connection materially increases exposure."
                    ),
                    remediation="Keep MaxAuthTries at 6 or lower.",
                    location=directive.location,
                )
        elif keyword == "LoginGraceTime":
            if value.isdigit() and int(value) > 60:
                report.add(
                    check="ssh.login-grace-time",
                    title=f"LoginGraceTime is {value}s (default 120)",
                    severity="low",
                    detail=(
                        "A long grace period allows an attacker many parallel authentication attempts "
                        "per connection, which partially defeats MaxAuthTries."
                    ),
                    remediation="Set LoginGraceTime 30 or lower.",
                    location=directive.location,
                )
        elif keyword == "X11Forwarding" and lowered in TRUTHY:
            report.add(
                check="ssh.x11-forwarding",
                title="X11 forwarding is enabled on a server",
                severity="low",
                detail=(
                    "X11 forwarding is a client feature. On a server it only adds attack surface, "
                    "and forwarded sessions can be observed."
                ),
                remediation="Set X11Forwarding no unless someone genuinely needs graphical sessions.",
                location=directive.location,
            )
        elif keyword == "AllowUsers":
            report.add(
                check="ssh.allow-users",
                title="AllowUsers restricts who may log in (good)",
                severity="info",
                detail=f"Only {value} may authenticate over SSH, which limits the account surface.",
                remediation="Keep this list in sync with the roster and remove departed accounts.",
                location=directive.location,
            )


def _default_is_weak(keyword: str, default: str) -> bool:
    if keyword == "PasswordAuthentication":
        return default.lower() in TRUTHY
    if keyword == "PermitRootLogin":
        return default.lower() in ("yes", "true", "1")
    if keyword == "PermitEmptyPasswords":
        return default.lower() in TRUTHY
    if keyword == "MaxAuthTries":
        return default.isdigit() and int(default) > 6
    if keyword == "LoginGraceTime":
        return default.isdigit() and int(default) > 60
    if keyword == "X11Forwarding":
        return default.lower() in TRUTHY
    return False


def _check_algorithms(report: Report, parsed: ParsedConfig) -> None:
    groups = (
        ("KexAlgorithms", WEAK_KEX, STRONG_KEX, "key exchange"),
        ("Ciphers", WEAK_CIPHERS, STRONG_CIPHERS, "cipher"),
        ("MACs", WEAK_MACS, STRONG_MACS, "MAC"),
        ("HostKeyAlgorithms", WEAK_HOST_KEYS, STRONG_HOST_KEYS, "host key"),
    )

    for keyword, weak, strong, label in groups:
        directive = parsed.effective(keyword)
        offered: list[str]
        if directive is None:
            offered = []
            source = "(compiled-in default)"
        else:
            offered = [v.strip().lower() for v in directive.value.split(",") if v.strip()]
            source = directive.location

        found = sorted({w for w in weak if any(w == o or o.startswith(w.rstrip("*")) for o in offered)})
        if directive is None:
            report.add(
                check=f"ssh.{_snake(keyword)}",
                title=f"{keyword} is not pinned, so OpenSSH's default list applies",
                severity="medium",
                detail=(
                    f"sshd ships a default {label} list that has changed over time and has included "
                    "algorithms considered weak. An explicit list is reviewable and stable."
                ),
                remediation=f"Pin {keyword} to an explicit allowlist, for example {','.join(strong)}.",
                keyword=keyword,
            )
            continue

        if found:
            report.add(
                check=f"ssh.{_snake(keyword)}",
                title=f"Weak {label} algorithms allowed: {', '.join(found)}",
                severity="high",
                detail=(
                    f"{keyword} still permits {', '.join(found)}. These are the algorithms that "
                    "downgrade and key-recovery research targets."
                ),
                remediation=f"Remove them, leaving {','.join(strong)}.",
                keyword=keyword,
                weak=found,
                location=source,
            )
        elif not any(o in strong for o in offered):
            report.add(
                check=f"ssh.{_snake(keyword)}",
                title=f"{keyword} names no currently recommended algorithm",
                severity="medium",
                detail=f"Configured value: {directive.value[:120]}",
                remediation=f"Use a current allowlist such as {','.join(strong)}.",
                keyword=keyword,
            )
        else:
            report.add(
                check=f"ssh.{_snake(keyword)}",
                title=f"{keyword} is pinned to current algorithms (good)",
                severity="info",
                detail=f"{directive.value[:120]}",
                remediation="No action; re-review on each OpenSSH upgrade.",
                location=source,
            )


def _check_presence(report: Report, parsed: ParsedConfig) -> None:
    match_blocks = parsed.all_for("Match")
    report.data["match_blocks_detail"] = [
        {"context": d.context, "value": d.value, "source": d.source_file, "line": d.line_no}
        for d in match_blocks
    ]

    if match_blocks:
        report.add(
            check="ssh.match-blocks",
            title=f"{len(match_blocks)} Match block(s) override the global policy",
            severity="medium",
            detail=(
                "Settings inside a Match block apply only to the matching connections, and sshd "
                "uses the first value it finds. A permissive setting inside a Match block "
                "silently re-opens the account you just hardened. Blocks found: "
                + ", ".join(f"{d.context} [{d.value}]" for d in match_blocks[:6])
            ),
            remediation="Read each Match block and confirm it does not re-enable password or root login for a subset of connections.",
            count=len(match_blocks),
        )

    log_level = parsed.effective("LogLevel")
    if log_level is None or log_level.value.upper() in ("INFO", "QUIET"):
        report.add(
            check="ssh.logging",
            title="SSH logging is too coarse to investigate attempts",
            severity="medium",
            detail=(
                f"LogLevel is {'absent (defaults to INFO)' if log_level is None else log_level.value}. "
                "Successful and failed authentications are logged, but the detail needed to "
                "correlate an attack is not."
            ),
            remediation="Set LogLevel VERBOSE so failed logins record the key and algorithm used.",
        )
    else:
        report.add(
            check="ssh.logging",
            title=f"LogLevel is {log_level.value} (sufficient for investigation)",
            severity="info",
            detail="Verbose logging is enabled, so authentication attempts can be reconstructed.",
            remediation="No action; make sure these logs are shipped off-host.",
        )


def _check_compression(report: Report, parsed: ParsedConfig) -> None:
    directive = parsed.effective("Compression")
    if directive is not None and directive.value.strip().lower() in TRUTHY:
        report.add(
            check="ssh.compression",
            title="SSH compression is enabled",
            severity="low",
            detail=(
                "Compression before encryption enables the CRIME attack, where an attacker who can "
                "observe traffic and inject chosen plaintext recovers encrypted secrets."
            ),
            remediation="Set Compression no.",
            location=directive.location,
        )

    protocol = parsed.effective("Protocol")
    if protocol is not None and "1" in protocol.value.replace(" ", ""):
        report.add(
            check="ssh.protocol",
            title="SSH protocol version 1 is permitted",
            severity="critical",
            detail=(
                "SSHv1 has no protection against man-in-the-middle attacks and is fundamentally "
                "unfixable. It is removed from current OpenSSH builds."
            ),
            remediation="Remove the Protocol directive entirely; modern sshd speaks version 2 only.",
            location=protocol.location,
        )


# --- live probe -----------------------------------------------------------


def probe(
    host: str, port: int = 22, timeout: float = DEFAULT_TIMEOUT, on_result: Any = None
) -> dict[str, Any]:
    """Connect, read the version banner, and exchange key proposals.

    No authentication is attempted. The KEXINIT exchange is unauthenticated and
    is exactly how a client learns what the server supports, so this reveals the
    full algorithm list without a single credential.
    """
    result: dict[str, Any] = {"connected": False, "host": host, "port": port}

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            result["connected"] = True

            banner = b""
            while b"\n" not in banner and len(banner) < 512:
                chunk = sock.recv(256)
                if not chunk:
                    break
                banner += chunk
            result["banner"] = banner.decode("utf-8", "replace").strip()

            algorithms = _exchange_kexinit(sock)
            if algorithms:
                result.update(algorithms)
    except (TimeoutError, OSError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"

    if on_result is not None:
        on_result(result)
    return result


def _exchange_kexinit(sock: socket.socket) -> dict[str, Any]:
    """Send our KEXINIT and read the server's, then parse the algorithm lists."""
    try:
        payload = _build_kexinit()
        sock.sendall(payload)

        buffer = b""
        while len(buffer) < 4096:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > 6 and buffer[5] == 20:  # SSH_MSG_KEXINIT
                break
    except OSError:
        return {}

    if len(buffer) < 6 or buffer[5] != 20:
        return {}

    try:
        length = int.from_bytes(buffer[0:4], "big")
        body = buffer[5 : 5 + length - 1]
        return _parse_kexinit(body)
    except (ValueError, IndexError):
        return {}


def _build_kexinit() -> bytes:
    """A minimal, valid client KEXINIT advertising only safe algorithms."""
    cookie = b"\x00" * 16

    def name_list(names: list[str]) -> bytes:
        joined = b",".join(n.encode() for n in names)
        return len(joined).to_bytes(4, "big") + joined

    kex = name_list(list(STRONG_KEX[:2]))
    host_key = name_list(["ssh-ed25519", "ecdsa-sha2-nistp256"])
    cipher_cs = name_list(list(STRONG_CIPHERS[:3]))
    cipher_sc = cipher_cs
    mac_cs = name_list(list(STRONG_MACS))
    mac_sc = mac_cs
    comp_cs = name_list(["none"])
    comp_sc = comp_cs
    lang_cs = name_list([""])
    lang_sc = name_list([""])

    payload = (
        b"\x0a"
        + cookie
        + kex
        + host_key
        + cipher_cs
        + cipher_sc
        + mac_cs
        + mac_sc
        + comp_cs
        + comp_sc
        + lang_cs
        + lang_sc
        + b"\x00"
        + b"\x00\x00\x00\x00"
    )
    padding_length = 8
    packet_length = 1 + len(payload) + padding_length
    padding = b"\x00" * padding_length
    return packet_length.to_bytes(4, "big") + b"\x06" + payload + padding


_KEXINIT_LISTS = ("kex", "host_key", "cipher_c2s", "cipher_s2c", "mac_c2s", "mac_s2c", "comp_c2s", "comp_s2c")


def _parse_kexinit(body: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {}
    offset = 17  # message type byte + 16-byte cookie

    for field_name in _KEXINIT_LISTS:
        if offset + 4 > len(body):
            break
        length = int.from_bytes(body[offset : offset + 4], "big")
        offset += 4
        if length == 0:
            out[field_name] = []
            continue
        raw = body[offset : offset + length]
        offset += length
        out[field_name] = [item.decode("utf-8", "replace") for item in raw.split(b",") if item]

    return out


def audit_live(host: str, address: str, port: int = 22, timeout: float = DEFAULT_TIMEOUT) -> Report:
    """Audit a live SSH service without authenticating."""
    report = Report(module="ssh_audit", target=f"{address}:{port}")

    with Timer(report):
        console.info(f"probing {address}:{port} (no authentication attempted)")
        result = probe(address, port, timeout=timeout)
        report.data.update({k: v for k, v in result.items() if k != "banner_bytes"})

        if not result["connected"]:
            report.add(
                check="ssh.unreachable",
                title="SSH service could not be reached",
                severity="info",
                detail=result.get("error", "connection failed"),
                remediation="Confirm sshd is listening on this port and reachable from here.",
            )
            return report

        banner = result.get("banner", "")
        report.data["banner"] = banner
        color = console.enable_color()
        console.kv("banner", banner or "-", color=color)

        version = _parse_banner_version(banner)
        if version:
            report.data["openssh_version"] = version
            if _version_outdated(version):
                report.add(
                    check="ssh.outdated-version",
                    title=f"OpenSSH {version} is past end of life",
                    severity="high",
                    detail=(
                        f"The banner reports OpenSSH {version}. Older branches no longer receive "
                        "security fixes, and sshd is directly exposed to the network."
                    ),
                    remediation="Upgrade to a currently supported OpenSSH release.",
                    version=version,
                )
            else:
                report.add(
                    check="ssh.version",
                    title=f"OpenSSH {version} reported",
                    severity="info",
                    detail="The version string was parsed from the pre-authentication banner.",
                    remediation="Keep it patched; sshd is internet-facing in many deployments.",
                )
        else:
            report.add(
                check="ssh.banner-unparsed",
                title="Could not parse the SSH version banner",
                severity="low",
                detail=f"Banner: {banner!r}",
                remediation="Confirm the service is actually SSH and not a honeypot or protocol multiplexer.",
            )

        kex = result.get("kex") or []
        ciphers = result.get("cipher_c2s") or []
        macs = result.get("mac_c2s") or []
        host_keys = result.get("host_key") or []

        if kex or ciphers:
            report.data["algorithms"] = {
                "kex": kex,
                "host_key": host_keys,
                "cipher": ciphers,
                "mac": macs,
            }
            print()
            console.kv("offered key exchange", ", ".join(kex[:4]) or "-", color=color)
            console.kv("offered host keys", ", ".join(host_keys[:4]) or "-", color=color)
            console.kv("offered ciphers", ", ".join(ciphers[:6]) or "-", color=color)
            console.kv("offered MACs", ", ".join(macs[:4]) or "-", color=color)

            _flag_offers(report, "kex", kex, WEAK_KEX, STRONG_KEX, "key exchange")
            _flag_offers(report, "cipher", ciphers, WEAK_CIPHERS, STRONG_CIPHERS, "cipher")
            _flag_offers(report, "mac", macs, WEAK_MACS, STRONG_MACS, "MAC")
            _flag_offers(report, "host_key", host_keys, WEAK_HOST_KEYS, STRONG_HOST_KEYS, "host key")
        else:
            report.add(
                check="ssh.no-kexinit",
                title="Server did not complete a key exchange proposal",
                severity="low",
                detail=(
                    "The banner was read but no algorithm list came back. This is normal for a "
                    "server that requires a specific client version, or for a non-SSH service."
                ),
                remediation="Confirm with `ssh -vvv -p PORT user@host` from a trusted host to see the proposal.",
            )

    return report


def _flag_offers(
    report: Report, label: str, offered: list[str], weak: frozenset[str], strong: tuple[str, ...], human: str
) -> None:
    if not offered:
        return

    lowered = [o.lower() for o in offered]
    bad = sorted({w for w in weak if w in lowered})
    good = [s for s in strong if s in lowered]

    if bad:
        report.add(
            check=f"ssh.weak-{label.replace('_', '-')}",
            title=f"Server offers weak {human} algorithms: {', '.join(bad)}",
            severity="high",
            detail=(
                f"The pre-authentication proposal still includes {', '.join(bad)}. An attacker who "
                "can influence negotiation can force the weakest mutually supported option."
            ),
            remediation=f"Restrict the server to {','.join(strong)}.",
            offered=bad,
        )
    if not good:
        report.add(
            check=f"ssh.no-strong-{label.replace('_', '-')}",
            title=f"Server offers no recommended {human} algorithm",
            severity="medium",
            detail=f"Offered: {', '.join(offered[:10])}",
            remediation=f"Enable at least one of {','.join(strong)}.",
            offered=offered[:20],
        )


def _parse_banner_version(banner: str) -> str | None:
    match = re.search(r"OpenSSH[_-](\d+\.\d+)", banner)
    if match:
        return match.group(1)
    match = re.search(r"SSH-2\.0-([^\s]+)", banner)
    return match.group(1) if match else None


#: Oldest branch still receiving security updates, as of the current release cycle.
_SUPPORTED_MAJORS = {"10", "9"}


def _version_outdated(version: str) -> bool:
    major = version.split(".", maxsplit=1)[0]
    if major.isdigit():
        return int(major) < 9
    return False


def fingerprint_authorized_key(line: str) -> str | None:
    """Return the SHA-256 fingerprint of an authorized_keys line, or None."""
    parts = line.split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except Exception:
        return None
    import hashlib

    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
