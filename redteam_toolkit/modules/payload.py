"""Detection engineering: rules, IOC extraction, and log triage.

This module replaces the original "payload generator", which printed a one-line
reverse-shell string. Printing a callback command teaches an attacker and helps
nobody defensive, so the capability was changed rather than extended.

What is here instead is what you actually need after an incident: a catalogue
of detection rules mapped to MITRE ATT&CK, a matcher that applies them to a log
line or any text, and an IOC extractor. Feed this module the tail of a log file
and it will tell you which techniques that text resembles and what to grep for
next.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..models import Report, Timer
from ..utils import console

# --- detection rules ------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Rule:
    """A single detection rule.

    ``pattern`` is a case-insensitive regular expression matched against a log
    line. ``why`` explains the technique in the terms a responder needs, and
    ``hunt`` gives the next query to run once the rule fires.
    """

    rule_id: str
    name: str
    pattern: str
    severity: str
    attack: str
    technique: str
    why: str
    hunt: str

    def compiled(self) -> re.Pattern[str]:
        return re.compile(self.pattern, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        rule_id="RTT-001",
        name="Reverse shell established over bash /dev/tcp",
        pattern=r"bash\s+-i\s*>&\s*/dev/(?:tcp|udp)/|nc\s+-[a-z]*e?\s+/bin/(?:ba)?sh|\bpython[23]?\s+-c\s+['\"].*socket.*(connect|SOCK_STREAM)|/dev/tcp/\d{1,3}(?:\.\d{1,3}){3}/\d+",
        severity="critical",
        attack="TA0002",
        technique="T1059.004 Unix Shell / T1071.001 Application Layer Protocol",
        why=(
            "This is the syntax of an interactive shell being tunnelled over a raw socket. In a "
            "web server log it means an uploaded script executed; in a proxy log it means an "
            "outbound connection to an attacker-controlled port."
        ),
        hunt=(
            "grep for any process whose command line contains /dev/tcp, and alert on outbound "
            "connections from web server accounts to ports 4444, 9001, 1337 and 31337."
        ),
    ),
    Rule(
        rule_id="RTT-002",
        name="Webshell written into the web root",
        pattern=r"\.php[\s'\"].*(?:eval|assert|base64_decode|system|passthru|shell_exec|popen|proc_open)\s*\(|eval\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE)|(?:echo|print)\s+.*(?:shell_exec|passthru)\s*\(",
        severity="critical",
        attack="TA0003",
        technique="T1505.003 Web Shell",
        why=(
            "Server-side script code that evaluates request parameters is a webshell. These are "
            "frequently delivered as a .php file written through a file-upload or file-inclusion bug."
        ),
        hunt=(
            "Find recently modified .php/.jsp files under the web root, then search them for "
            "eval, base64_decode and $_REQUEST. Compare modification times against deploy times."
        ),
    ),
    Rule(
        rule_id="RTT-003",
        name="Scheduled task persistence",
        pattern=r"\b(crontab\s+-|/etc/cron\.(?:d|daily|hourly)|schtasks\s+/create|at\s+\d{1,2}:\d{2}|systemd-run\s+--on)",
        severity="high",
        attack="TA0003",
        technique="T1053 Scheduled Task/Job",
        why=(
            "Job scheduling is the cheapest persistence mechanism: it re-launches the implant after "
            "a reboot without touching any service configuration."
        ),
        hunt="List all crontabs and systemd timers, and alert on any created outside a change window.",
    ),
    Rule(
        rule_id="RTT-004",
        name="SSH authorized_keys modified",
        pattern=r"authorized_keys|\.ssh/(?:id_(?:rsa|ed25519|dsa))|ssh-copy-id",
        severity="high",
        attack="TA0003",
        technique="T1098.004 SSH Authorized Keys",
        why=(
            "Adding a public key grants passwordless access to whoever holds the matching private "
            "key. It leaves no failed-login trail, which is why it is preferred over guessing."
        ),
        hunt="Audit every authorized_keys file and its mtime; require key registration through a ticket.",
    ),
    Rule(
        rule_id="RTT-005",
        name="Cleartext credential protocol in use",
        pattern=r"\b(telnet|ftp|rsh|rlogin|imap\s+143|pop3\s+110)\b|cleartext\s+password|plain\s*[- ]?text\s+login",
        severity="medium",
        attack="TA0006",
        technique="T1040 Network Sniffing / T1552 Unsecured Credentials",
        why=(
            "Legacy protocols carry credentials in the clear. Anyone on the network path, including "
            "a coffee-shop Wi-Fi client, can read them directly."
        ),
        hunt="Alert on connections to ports 21, 23, 110 and 143, and inventory whether each is still required.",
    ),
    Rule(
        rule_id="RTT-006",
        name="Encoded or obfuscated command execution",
        pattern=r"powershell[^\n]{0,80}(?:-enc|-encodedcommand|-e\s)|FromBase64String|Invoke-Expression|\biex\s+|\-w\s+hidden\s+-enc|echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64",
        severity="high",
        attack="TA0005",
        technique="T1027 Obfuscated Files or Information / T1059.001 PowerShell",
        why=(
            "Base64-wrapped commands defeat keyword-based logging because the payload never appears "
            "in plaintext. This is a reliable sign of deliberate concealment."
        ),
        hunt=(
            "Log script-block text for PowerShell, and alert on powershell.exe started by a web "
            "server or office application process."
        ),
    ),
    Rule(
        rule_id="RTT-007",
        name="New account or group membership added",
        pattern=r"(?:useradd|adduser|usermod\s+-aG|net\s+user\s+\S+\s+/add|New-NetLocalUser|dsadd\s+user)\b.*(?:\sadmin|\sroot|\ssudo)",
        severity="high",
        attack="TA0003",
        technique="T1136.001 Create Account: Local",
        why=(
            "Attackers add a backdoor account once they have write access, because it is far more "
            "reliable than the persistence techniques that can be detected and cleaned up."
        ),
        hunt="Alert on any local account creation, and reconcile the account list against the HR roster weekly.",
    ),
    Rule(
        rule_id="RTT-008",
        name="Shadow or passwd file tampered with",
        pattern=r"/etc/(?:shadow|passwd)\b|usermod\s+-p|pwconv|chpasswd\b|vipw",
        severity="high",
        attack="TA0005",
        technique="T1098 Account Manipulation",
        why=(
            "Direct edits to the credential files, or a password change made without going through "
            "the normal account management path, is how a foothold is made permanent."
        ),
        hunt="Enable auditd on /etc/shadow and /etc/passwd; any write should generate a ticket.",
    ),
    Rule(
        rule_id="RTT-009",
        name="Discovery commands run in sequence",
        pattern=r"\b(?:whoami|id\s+;?\s*uname|uname\s+-a|cat\s+/etc/passwd|ifconfig|ip\s+a(?:ddr)?\b|netstat\s+-tulnp|systeminfo|Get-Process|ls\s+-la?\s+/|env\s*\|)",
        severity="low",
        attack="TA0007",
        technique="T1082 System Information Discovery / T1083 File and Directory Discovery",
        why=(
            "Low severity alone, but a burst of these within a short window is reconnaissance. "
            "Individually they look like normal administration."
        ),
        hunt=(
            "Correlate: more than five distinct discovery commands from one process tree in five "
            "minutes is a strong signal, even when each command is legitimate."
        ),
    ),
    Rule(
        rule_id="RTT-010",
        name="Suspicious download to a shell or temp directory",
        pattern=r"\b(?:curl|wget|Invoke-WebRequest|iwr)\b[^\n]{0,120}?(?:\|\s*(?:ba)?sh|;|&&|>/tmp/|/dev/shm/)",
        severity="high",
        attack="TA0002",
        technique="T1105 Ingress Tool Transfer",
        why=(
            "Downloading a script and piping it straight to a shell leaves no file for antivirus or "
            "an investigator to examine. It is one of the most common post-exploitation steps."
        ),
        hunt="Alert on curl/wget executed by a service account, and on any write into /tmp or /dev/shm.",
    ),
    Rule(
        rule_id="RTT-011",
        name="Log tampering or clearing",
        pattern=r"\b(?:history\s+-c|>\s*/var/log/|rm\s+-rf?\s+/var/log|logrotate\s+-f|wevtutil\s+cl|truncate\s+-s\s*0)",
        severity="critical",
        attack="TA0005",
        technique="T1070.001 Clear Linux or Mac System Logs",
        why=(
            "Deleting logs is an admission of compromise, not a normal action. Treat the host as "
            "already lost and rebuild it rather than cleaning it."
        ),
        hunt="Ship logs off-host in real time so client-side deletion has no effect on your copy.",
    ),
    Rule(
        rule_id="RTT-012",
        name="Reverse DNS / DNS tunnelling indicator",
        pattern=r"\b[a-z0-9+/]{40,}={0,2}\.[a-z0-9-]+\.(?:com|net|org|io)\b|nslookup\s+.*\$\(|dig\s+\+short\s+.*\$\(",
        severity="high",
        attack="TA0011",
        technique="T1572 Protocol Tunneling",
        why=(
            "A long encoded label in a DNS query, or a lookup whose argument is a shell variable, is "
            "either tunnelling data out over DNS or an interactive resolver the attacker set up."
        ),
        hunt="Baseline the volume and length of DNS labels per host; alerts on average label length over 40 characters.",
    ),
    Rule(
        rule_id="RTT-013",
        name="Container or namespace escape primitive referenced",
        pattern=r"/proc/\d+/(?:root|ns)/|nsenter\s+--target\s+1|docker\.sock|mount\s+.*\/dev\/(?:sd|vd)",
        severity="critical",
        attack="TA0004",
        technique="T1611 Escape to Host",
        why=(
            "Reaching into /proc/1/root, entering the host mount namespace, or touching the Docker "
            "socket is the standard route from a container to the host."
        ),
        hunt="Alert on any container process referencing the Docker socket, and mount the socket read-only or not at all.",
    ),
    Rule(
        rule_id="RTT-014",
        name="Sudo or privilege escalation invoked non-interactively",
        pattern=r"sudo\s+-S\b|echo\s+[^|]*\|\s*sudo\s|su\s+-\s*$|pkexec\b.*\bnopasswd|setcap\s+cap_",
        severity="medium",
        attack="TA0004",
        technique="T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        why=(
            "Feeding a password to sudo through a pipe, or granting a file capability, automates "
            "privilege escalation in a way that is invisible in normal audit review."
        ),
        hunt="Record all sudo invocations with the invoking process; interactive shells are the norm.",
    ),
)

RULES_BY_ID = {rule.rule_id: rule for rule in RULES}


# --- IOC extraction -------------------------------------------------------

_IOC_PATTERNS: tuple[tuple[str, str], ...] = (
    ("ipv4", r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
    ("ipv6", r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
    ("url", r"\bhttps?://[^\s\"'<>\\)\]]+"),
    ("email", r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    (
        "domain",
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|info|biz|ru|cn|top|xyz|co|uk|de|fr|nl|br|in|jp|au|ca|eu|dev|app|onion)\b",
    ),
    ("md5", r"\b[a-fA-F0-9]{32}\b"),
    ("sha1", r"\b[a-fA-F0-9]{40}\b"),
    ("sha256", r"\b[a-fA-F0-9]{64}\b"),
    ("registry_key", r"\b(?:HKLM|HKCU|HKCR|HKU|HKCC)\\(?:SOFTWARE|SYSTEM)\\[^\s\"',;]+"),
    ("unix_path", r"(?<![\w/])/(?:etc|var|usr|bin|sbin|opt|home|root|tmp|dev|proc|sys)/[\w./-]+"),
    ("windows_path", r"\b[A-Za-z]:\\(?:Windows|Users|ProgramData|AppData|Temp)\\[\w\\. -]+"),
    ("onion", r"\b[a-z2-7]{16,56}\.onion\b"),
    ("btc", r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
)

#: Networks that must never reach a blocklist. Prefix matching on "10." is not
#: enough: 172.16.0.0/12 is an entire /12 of private space, and string prefixes
#: miss it entirely.
_UNBLOCKABLE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("198.18.0.0/15"),
    # TEST-NET-1/2/3 are reserved for documentation, so they appear in
    # documentation and lab logs constantly and would block nothing real.
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def _is_unblockable(address: str) -> bool:
    """True for an address that must not be published as a blocklist indicator."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(ip in network for network in _UNBLOCKABLE_NETWORKS)


def extract_iocs(text: str) -> dict[str, list[str]]:
    """Pull indicators of compromise out of arbitrary text, de-duplicated."""
    found: dict[str, list[str]] = {}
    for kind, pattern in _IOC_PATTERNS:
        matches: list[str] = []
        seen: set[str] = set()
        for match in re.findall(pattern, text):
            value = match.rstrip(".,;:)]}\"'")
            if not value or value in seen:
                continue
            if kind == "ipv4" and _is_unblockable(value):
                continue
            seen.add(value)
            matches.append(value)
        if matches:
            found[kind] = matches
    return found


# --- matching -------------------------------------------------------------


@dataclass(slots=True)
class Match:
    """A rule that fired on a line of text."""

    rule: Rule
    line_no: int
    line: str
    matched: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.rule_id,
            "name": self.rule.name,
            "severity": self.rule.severity,
            "attack": self.rule.attack,
            "technique": self.rule.technique,
            "line": self.line_no,
            "matched": self.matched,
        }


def match_line(line: str, line_no: int = 0, rules: Sequence[Rule] | None = None) -> list[Match]:
    """Apply every rule to one line. Returns all matches, not just the first."""
    out: list[Match] = []
    for rule in rules if rules is not None else RULES:
        found = rule.compiled().search(line)
        if found:
            out.append(Match(rule, line_no, line[:300], found.group(0)[:120]))
    return out


def match_text(text: str, max_matches: int = 200, rules: Sequence[Rule] | None = None) -> list[Match]:
    """Apply every rule to a block of text, line by line."""
    catalogue = list(rules) if rules is not None else list(RULES)
    out: list[Match] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        out.extend(match_line(line, line_no, catalogue))
        if len(out) >= max_matches:
            break
    return out[:max_matches]


# --- report wrappers ------------------------------------------------------


def build_rules_report() -> Report:
    """Return the full rule catalogue as a report, for documentation output."""
    report = Report(module="payload", target="(rule catalogue)")
    report.data["rule_count"] = len(RULES)
    report.data["rules"] = [
        {
            "id": rule.rule_id,
            "name": rule.name,
            "severity": rule.severity,
            "attack": rule.attack,
            "technique": rule.technique,
            "pattern": rule.pattern,
            "why": rule.why,
            "hunt": rule.hunt,
        }
        for rule in RULES
    ]
    report.data["reframed_from"] = (
        "This module previously printed a reverse-shell command string. It now provides "
        "detection rules and IOC extraction instead."
    )
    return report


def detect(text: str, source: str = "(stdin)", extra_rules: Iterable[Rule] = ()) -> Report:
    """Triage a block of log text against the rule catalogue."""
    report = Report(module="payload", target=source)
    with Timer(report):
        custom = list(extra_rules)
        # A custom rule may reuse a built-in identifier, so the merged catalogue
        # is keyed by id with the custom definition winning.
        catalogue: dict[str, Rule] = {rule.rule_id: rule for rule in RULES}
        catalogue.update({rule.rule_id: rule for rule in custom})
        rules = sorted(catalogue.values(), key=lambda r: r.rule_id)

        matches = match_text(text, rules=rules)
        iocs = extract_iocs(text)
        lines = [line for line in text.splitlines() if line.strip()]

        report.data["lines"] = len(lines)
        report.data["rules_evaluated"] = len(rules)
        report.data["match_count"] = len(matches)
        report.data["rules_hit"] = sorted({m.rule.rule_id for m in matches})
        report.data["iocs"] = iocs
        report.data["ioc_count"] = sum(len(v) for v in iocs.values())
        report.data["matches"] = [m.to_dict() for m in matches[:50]]

        _emit_console(matches, iocs)

        seen: set[str] = set()
        for match in matches:
            if match.rule.rule_id in seen:
                continue
            seen.add(match.rule.rule_id)
            rule = match.rule
            report.add(
                check=f"detect.{rule.rule_id.lower()}",
                title=f"{rule.name} ({rule.rule_id})",
                severity=rule.severity,
                detail=f"{rule.why}\n\nObserved: {match.line[:200]}",
                remediation=f"Hunt: {rule.hunt}",
                attack=rule.attack,
                technique=rule.technique,
                occurrences=sum(1 for m in matches if m.rule.rule_id == rule.rule_id),
            )

        if iocs:
            external = {
                kind: values for kind, values in iocs.items() if kind in ("ipv4", "domain", "url", "onion")
            }
            if external:
                report.add(
                    check="detect.iocs",
                    title=f"{sum(len(v) for v in external.values())} indicator(s) extracted for blocking",
                    severity="medium",
                    detail=(
                        "Indicators worth reviewing: "
                        + ", ".join(f"{k}={v[:4]}" for k, v in list(external.items())[:6])
                    ),
                    remediation=(
                        "Validate each indicator against a threat feed before blocking; test files "
                        "and internal ranges produce false positives. Never block on a raw regex match alone."
                    ),
                    iocs={k: v[:10] for k, v in external.items()},
                )

        if not matches:
            report.add(
                check="detect.clean",
                title="No detection rule matched this text",
                severity="info",
                detail=(
                    f"{len(lines)} line(s) were evaluated against {len(RULES)} rules with no hit. "
                    "Absence of a match is not evidence of absence: the catalogue covers common "
                    "Linux and Windows behaviours, not everything."
                ),
                remediation="Keep the rule set updated as new techniques are observed in your environment.",
            )

    return report


def _emit_console(matches: list[Match], iocs: dict[str, list[str]]) -> None:
    color = console.enable_color()
    if matches:
        console.kv("rules matched", str(len(matches)), color=color)
        console.emit()
        console.table(
            ["rule", "severity", "name", "line", "matched"],
            [
                [
                    m.rule.rule_id,
                    console.paint(m.rule.severity, m.rule.severity, color),
                    m.rule.name,
                    str(m.line_no),
                    m.matched,
                ]
                for m in matches[:15]
            ],
            color=color,
        )
    else:
        console.kv("rules matched", "0", color=color)

    if iocs:
        console.emit()
        console.kv("indicators extracted", str(sum(len(v) for v in iocs.values())), color=color)
        for kind, values in iocs.items():
            console.kv(f"  {kind}", ", ".join(values[:8]), color=color)


def parse_extra_rules(path: str) -> list[Rule]:
    """Load additional rules from a simple ``id|name|severity|pattern`` TSV."""
    out: list[Rule] = []
    with Path(path).open(encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|", 3)
            if len(parts) != 4:
                continue
            rule_id, name, severity, pattern = (p.strip() for p in parts)
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"{path}:{line_no}: invalid regex: {exc}") from exc
            out.append(
                Rule(
                    rule_id=rule_id,
                    name=name,
                    pattern=pattern,
                    severity=severity
                    if severity in ("info", "low", "medium", "high", "critical")
                    else "medium",
                    attack="-",
                    technique="-",
                    why="Locally defined rule.",
                    hunt="Review matches manually.",
                )
            )
    return out
