"""Firewall ruleset audit.

Parses the saved output of ``iptables-save``, ``nft list ruleset``,
``ufw status verbose`` and ``firewall-cmd --list-all`` from a file, and grades
the policy. This is the offline counterpart to the network scanner: the scanner
tells you what an attacker can reach, this tells you what the rules were meant
to do and where they contradict that.

The checks that catch real problems:

* a default ACCEPT policy, which turns the firewall into documentation
* missing ``ESTABLISHED,RELATED`` on the input path, which breaks return traffic
  and confuses stateful inspection
* SSH (22) reachable from anywhere, the single most-scanned port on the internet
* management and database ports exposed to the world
* DROP/REJECT used without a preceding rule that logs, so attacks are invisible
* SSH with a recent ``recent`` module, which is the correct control, contrasted
  with a bare ACCEPT
* rule ordering problems, such as an ACCEPT appearing before the restriction it
  was meant to be behind
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..models import Report, Timer
from ..utils import console

#: Ports that should essentially never be world-reachable.
MUST_NOT_EXPOSE: dict[int, tuple[str, str]] = {
    22: ("SSH", "high"),
    23: ("Telnet", "critical"),
    445: ("SMB", "critical"),
    3389: ("RDP", "high"),
    3306: ("MySQL", "high"),
    5432: ("PostgreSQL", "high"),
    6379: ("Redis", "critical"),
    27017: ("MongoDB", "critical"),
    9200: ("Elasticsearch", "high"),
    11211: ("Memcached", "critical"),
    5900: ("VNC", "high"),
    1433: ("MSSQL", "high"),
    21: ("FTP", "high"),
    25: ("SMTP", "high"),
    161: ("SNMP", "medium"),
    389: ("LDAP", "medium"),
    1521: ("Oracle", "high"),
}

#: Ports that are commonly open on purpose; not flagged just for being open.
EXPECTED_PUBLIC = frozenset({53, 80, 123, 443})

WORLD = frozenset({"0.0.0.0/0", "::/0", "anywhere", "any"})

_IPTABLES_LINE = re.compile(r"^-A\s+(?P<chain>\S+)\s+(?P<rest>.*)$")
_UFW_RULE = re.compile(
    r"^(?:(?P<port>\S+?)/(?P<proto>tcp|udp)\s+)?(?P<target>ALLOW|DENY|REJECT|LIMIT)\s+(?P<rest>.+)$",
    re.IGNORECASE,
)


@dataclass(slots=True)
class Rule:
    """One parsed rule from any supported ruleset format."""

    backend: str
    chain: str
    action: str
    protocol: str = "-"
    dport: str = "-"
    source: str = "-"
    destination: str = "-"
    raw: str = ""
    line_no: int = 0
    options: dict[str, str] = field(default_factory=dict)

    @property
    def is_world_inbound(self) -> bool:
        if self.action not in ("ACCEPT", "accept", "ALLOW", "LIMIT", "limit"):
            return False
        if self.source in WORLD or self.source in ("0.0.0.0", "::"):
            return True
        return self.source in ("-", "anywhere", "any")

    @property
    def is_stateful(self) -> bool:
        """True when the rule only accepts traffic belonging to an existing session.

        Such a rule cannot shadow anything, because new inbound connections never
        match it, so it must be excluded from ordering analysis.
        """
        haystack = f"{self.options.get('ctstate', '')} {self.options.get('state', '')} {self.raw}".upper()
        return "ESTABLISHED" in haystack

    @property
    def is_loopback(self) -> bool:
        return " -i lo" in f" {self.raw}" or self.options.get("i") == "lo"

    def to_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "chain": self.chain,
            "action": self.action,
            "protocol": self.protocol,
            "port": self.dport,
            "source": self.source,
        }


@dataclass(slots=True)
class Ruleset:
    backend: str
    rules: list[Rule] = field(default_factory=list)
    policies: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    @property
    def has_default_accept(self) -> bool:
        """True when a filtering chain defaults to ACCEPT.

        OUTPUT is excluded: an ACCEPT output policy is the normal, correct
        configuration, because a host must be able to make outbound connections.
        """
        filtering = ("INPUT", "FORWARD", "default")
        return any(
            policy.upper() == "ACCEPT"
            for chain, policy in self.policies.items()
            if chain.upper() in filtering
        )

    @property
    def open_filtering_chains(self) -> dict[str, str]:
        return {
            chain: policy
            for chain, policy in self.policies.items()
            if chain.upper() in ("INPUT", "FORWARD", "default") and policy.upper() == "ACCEPT"
        }

    def exposed_ports(self) -> dict[int, list[Rule]]:
        out: dict[int, list[Rule]] = {}
        for rule in self.rules:
            if not rule.is_world_inbound:
                continue
            for port in _expand_ports(rule.dport):
                out.setdefault(port, []).append(rule)
        return out


def _expand_ports(spec: str) -> list[int]:
    if spec in ("-", "", "any"):
        return []
    ports: list[int] = []
    for chunk in str(spec).split(","):
        part = chunk.strip()
        if not part:
            continue
        if "-" in part:
            start, _, end = part.partition("-")
            if start.isdigit() and end.isdigit():
                ports.extend(range(int(start), int(end) + 1))
        elif part.isdigit():
            ports.append(int(part))
    return ports


# --- parsing --------------------------------------------------------------


def parse(path: str | Path) -> Ruleset:
    """Parse a ruleset dump, detecting which backend produced it."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()

    if any("iptables" in line.lower() for line in lines[:12]) or any(
        line.startswith(("-A ", "*", "COMMIT")) for line in lines[:40]
    ):
        return _parse_iptables(lines)
    if any(re.search(r"\btable\s+(?:ip6?|inet|bridge|netdev)\b", line) for line in lines[:12]):
        return _parse_nft(lines)
    if any(
        line.startswith(("Status:", "To:", "Default:")) or _UFW_RULE.match(line.strip()) for line in lines
    ):
        return _parse_ufw(lines)
    if any("public:" in line or "services:" in line for line in lines):
        return _parse_firewalld(lines)

    return Ruleset(backend="unknown", warnings=[f"{path} did not match a known ruleset format"])


def _parse_iptables(lines: list[str]) -> Ruleset:
    ruleset = Ruleset(backend="iptables")

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        policy = re.match(r"^:(\S+)\s+(\S+)", line)
        if policy:
            ruleset.policies[policy.group(1)] = policy.group(2)
            continue

        match = _IPTABLES_LINE.match(line)
        if not match:
            continue

        rest = match.group("rest")
        tokens = rest.split()

        # The jump target is the action. Other flags (-m match, -p protocol,
        # -s source) appear before it, so the action cannot simply be tokens[0].
        action = ""
        protocol = "-"
        dport = "-"
        source = "-"
        destination = "-"
        options: dict[str, str] = {}
        index = 0

        while index < len(tokens):
            token = tokens[index]

            if token in ("-j", "--jump"):
                index += 1
                if index < len(tokens):
                    action = tokens[index].upper()
            elif token in ("-p", "--protocol"):
                index += 1
                if index < len(tokens):
                    protocol = tokens[index].lower()
            elif token in ("-s", "--source"):
                index += 1
                if index < len(tokens):
                    source = tokens[index]
            elif token in ("-d", "--destination"):
                index += 1
                if index < len(tokens):
                    destination = tokens[index]
            elif token.split("=", 1)[0] in ("--dport", "--destination-port", "--sport", "--source-port"):
                # Both the "--dport 443" and "--dport=443" spellings occur.
                name, sep, inline = token[2:].partition("=")
                if sep:
                    value = inline
                else:
                    index += 1
                    value = tokens[index] if index < len(tokens) else "-"
                if name in ("dport", "destination-port"):
                    dport = value
                options[name] = value
            elif token.startswith("--"):
                name, _, value = token[2:].partition("=")
                options[name] = value if _ else "true"
            index += 1

        if not action:
            # Non-jump lines such as ":CHAIN POLICY" are handled above; anything
            # else here is a declaration we do not model as a rule.
            continue

        if "log-prefix" in options or action.startswith("LOG"):
            options["log"] = "true"

        ruleset.rules.append(
            Rule(
                backend="iptables",
                chain=match.group("chain"),
                action=action,
                protocol=protocol,
                dport=dport,
                source=source,
                destination=destination,
                options=options,
                raw=line,
                line_no=line_no,
            )
        )

    if not ruleset.policies and not ruleset.rules:
        ruleset.warnings.append("iptables format detected but no rules were parsed")
    return ruleset


_NFT_VERDICTS = frozenset({"accept", "drop", "reject", "jump", "goto", "return", "log", "queue"})
_NFT_CHAIN_OPEN = re.compile(r"^chain\s+(\S+)")


def _parse_nft(lines: list[str]) -> Ruleset:
    """Parse ``nft list ruleset`` output.

    nft rule syntax is ``<match expressions...> <verdict> [comment]``, so the
    verdict is the last bare keyword on the line rather than the first, and the
    enclosing chain has to be tracked as the walk proceeds.
    """
    ruleset = Ruleset(backend="nftables")
    current_chain: str | None = None

    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if "hook" in line and "policy" in line:
            policy = re.search(r"policy\s+(\w+)", line)
            if policy:
                ruleset.policies["default"] = policy.group(1)
            continue

        chain_match = _NFT_CHAIN_OPEN.match(line)
        if chain_match:
            current_chain = chain_match.group(1)
            continue

        if re.match(r"^(?:table|set|map|element)\b", line) or line in ("{", "}"):
            continue

        if current_chain is None:
            continue

        action = next(
            (
                token.rstrip(";,{}").lower()
                for token in reversed(line.split())
                if token.rstrip(";,{}").lower() in _NFT_VERDICTS
            ),
            None,
        )
        if action is None:
            continue

        port_match = re.search(r"\bdport\s+(\S+)", line)
        dport = port_match.group(1).strip("'\"") if port_match else "-"

        source_match = re.search(r"\b(?:ip|ip6)\s+saddr\s+(\S+)", line)
        source = source_match.group(1).strip("'\"") if source_match else "-"

        ruleset.rules.append(
            Rule(
                backend="nftables",
                chain=current_chain,
                action=action.upper(),
                protocol="tcp" if " tcp " in f" {line} " else ("udp" if " udp " in f" {line} " else "-"),
                dport=dport,
                source=source,
                raw=line,
                line_no=line_no,
            )
        )

    return ruleset


def _parse_ufw(lines: list[str]) -> Ruleset:
    ruleset = Ruleset(backend="ufw")
    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("Default:"):
            policy = re.search(r"inactive \(reject incoming|active \(reject incoming|default (\w+)", line)
            if policy and policy.lastindex:
                ruleset.policies["input"] = policy.group(1)
            elif "inactive" in line:
                ruleset.policies["input"] = "ACCEPT"
            continue

        match = _UFW_RULE.match(line)
        if not match:
            continue

        target = match.group("target").upper()
        rest = match.group("rest")
        dport = match.group("port") or "-"
        source = "-"
        to_match = re.search(r"\bto\s+(\S+)", rest)
        if to_match:
            dport = to_match.group(1)
        from_match = re.search(r"\bfrom\s+(\S+)", rest)
        if from_match:
            source = from_match.group(1)
        else:
            # `ufw status verbose` prints the source as a positional column:
            #   5432/tcp   ALLOW   10.0.0.0/8
            # Anything other than "Anywhere" is a real restriction.
            column = rest.split()[0] if rest.split() else "Anywhere"
            if column.lower() not in ("anywhere", "any"):
                source = column
        proto = (match.group("proto") or "").lower()
        if not proto:
            proto = "tcp" if "/tcp" in rest else ("udp" if "/udp" in rest else "-")

        ruleset.rules.append(
            Rule(
                backend="ufw",
                chain="ufw-user-input",
                action=target,
                protocol=proto,
                dport=dport,
                source=source,
                raw=line,
                line_no=line_no,
            )
        )
    return ruleset


def _parse_firewalld(lines: list[str]) -> Ruleset:
    ruleset = Ruleset(backend="firewalld")
    for line_no, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        port = None
        service = None
        port_match = re.search(r"^(\d+)/(tcp|udp)\b", line)
        if port_match:
            port = port_match.group(1)
            proto = port_match.group(2)
        else:
            service_match = re.match(r"^([\w-]+)\s", line)
            if service_match:
                service = service_match.group(1)
            proto = ""
        if port or service:
            ruleset.rules.append(
                Rule(
                    backend="firewalld",
                    chain="public",
                    action="ACCEPT",
                    protocol=proto or "-",
                    dport=port or service or "-",
                    source="0.0.0.0/0",
                    raw=line,
                    line_no=line_no,
                )
            )
    return ruleset


# --- audit ----------------------------------------------------------------


def audit(path: str | Path) -> Report:
    """Audit a firewall ruleset dump."""
    rules_path = Path(path)
    report = Report(module="firewall_audit", target=str(rules_path))

    with Timer(report):
        if not rules_path.is_file():
            report.add(
                check="fw.dump-missing",
                title="Ruleset dump not found",
                severity="low",
                detail=f"{rules_path} does not exist or is not readable.",
                remediation=(
                    "Produce a dump first: `iptables-save > fw.txt`, `nft list ruleset > fw.txt`, "
                    "`ufw status verbose > fw.txt`, or `firewall-cmd --list-all > fw.txt`."
                ),
            )
            return report

        ruleset = parse(rules_path)
        report.data["backend"] = ruleset.backend
        report.data["rules_parsed"] = len(ruleset.rules)
        report.data["policies"] = ruleset.policies
        report.data["parse_warnings"] = ruleset.warnings
        report.data["chains"] = dict(Counter(rule.chain for rule in ruleset.rules))

        _emit_console(ruleset, rules_path)

        for warning in ruleset.warnings:
            report.add(
                check="fw.parse-warning",
                title="Ruleset could not be fully parsed",
                severity="low",
                detail=warning,
                remediation="Paste the full unedited output of the tool that produced it.",
            )

        if ruleset.backend == "unknown":
            report.add(
                check="fw.unknown-backend",
                title="Ruleset format not recognised",
                severity="low",
                detail="The dump did not match iptables, nftables, ufw or firewalld output.",
                remediation="Use the native dump command for the firewall in use on the host.",
            )
            return report

        _check_default_policy(report, ruleset)
        _check_stateful(report, ruleset)
        _check_exposure(report, ruleset)
        _check_logging(report, ruleset)
        _check_ordering(report, ruleset)
        _check_recent(report, ruleset)

    return report


def _emit_console(ruleset: Ruleset, path: Path) -> None:
    color = console.enable_color()
    console.kv("file", str(path), color=color)
    console.kv("backend", ruleset.backend, color=color)
    console.kv("rules parsed", str(len(ruleset.rules)), color=color)
    if ruleset.policies:
        for chain, policy in ruleset.policies.items():
            style = "bad" if policy.upper() == "ACCEPT" else "ok"
            console.kv(f"policy[{chain}]", console.paint(policy, style, color), color=color)

    exposed = ruleset.exposed_ports()
    if exposed:
        console.emit()
        console.kv("world-reachable ports", "", color=color)
        console.table(
            ["port", "action", "chain", "source", "service"],
            [
                [
                    port,
                    rule.action,
                    rule.chain,
                    rule.source,
                    MUST_NOT_EXPOSE.get(port, ("-", "-"))[0],
                ]
                for port, rules in sorted(exposed.items())
                for rule in rules[:1]
            ],
            color=color,
        )


def _check_default_policy(report: Report, ruleset: Ruleset) -> None:
    if not ruleset.policies:
        return
    if ruleset.has_default_accept:
        open_chains = ruleset.open_filtering_chains
        report.add(
            check="fw.default-accept",
            title="Default firewall policy is ACCEPT",
            severity="critical",
            detail=(
                f"Chain policies are {ruleset.policies}, and {', '.join(open_chains)} default(s) to "
                "ACCEPT. An ACCEPT default means the firewall only permits what has been explicitly "
                "allowed, and permits everything else too. The firewall is documentation, not a "
                "control, and any gap in the rules below it is a full exposure. OUTPUT is not "
                "flagged here: an ACCEPT output policy is the correct and expected setting."
            ),
            remediation=(
                "Set the input and forward policies to DROP, then add explicit accepts. Test in a "
                "maintenance window with console access available so you cannot lock yourself out."
            ),
            policies=dict(open_chains),
        )
    elif ruleset.policies:
        report.add(
            check="fw.default-drop",
            title="Default policy denies unsolicited traffic (good)",
            severity="info",
            detail=f"Chain policies are {ruleset.policies}, so anything not explicitly allowed is dropped.",
            remediation="Keep the default at DROP and add rules deliberately.",
        )


def _check_stateful(report: Report, ruleset: Ruleset) -> None:
    has_established = any(
        rule.options.get("ctstate", "").upper().find("ESTABLISHED") >= 0
        or "ESTABLISHED" in rule.raw.upper()
        or rule.options.get("state", "").upper().find("ESTABLISHED") >= 0
        for rule in ruleset.rules
    )
    if ruleset.backend == "ufw":
        has_established = True  # ufw installs this by default

    if not has_established:
        report.add(
            check="fw.no-stateful-return",
            title="No ESTABLISHED,RELATED accept rule on the input path",
            severity="high",
            detail=(
                "Without a rule accepting ESTABLISHED,RELATED traffic, return packets are treated "
                "as unsolicited and dropped. Beyond breaking outbound connections, it means "
                "connection tracking is not being used, so the firewall cannot spot established "
                "sessions an attacker is riding."
            ),
            remediation="Add an early accept for `-m conntrack --ctstate RELATED,ESTABLISHED`.",
        )
    else:
        report.add(
            check="fw.stateful-return",
            title="Connection tracking is configured (good)",
            severity="info",
            detail="An ESTABLISHED,RELATED accept rule is present, so stateful inspection is active.",
            remediation="No action.",
        )


def _check_exposure(report: Report, ruleset: Ruleset) -> None:
    exposed = ruleset.exposed_ports()

    for port, rules in sorted(exposed.items()):
        if port in EXPECTED_PUBLIC:
            continue
        service, severity = MUST_NOT_EXPOSE.get(port, (f"port {port}", "medium"))
        actions = {rule.action for rule in rules}
        mitigated = "LIMIT" in actions or "rate" in " ".join(r.raw for r in rules).lower()

        if mitigated:
            report.add(
                check="fw.exposed-rate-limited",
                title=f"{service} ({port}) is world-reachable but rate limited",
                severity="low",
                detail=(
                    f"Port {port} accepts from any source, but a rate limit is applied. That is the "
                    "correct pattern for an administrative port that must stay reachable."
                ),
                remediation="Keep the rate limit, and confirm the alert fires when it trips.",
                port=port,
            )
            continue

        report.add(
            check="fw.world-reachable",
            title=f"{service} on port {port} is reachable from any address",
            severity=severity,
            detail=(
                f"{len(rules)} rule(s) accept traffic to port {port} from 0.0.0.0/0, with no rate "
                f"limit. This is the single most common finding in a perimeter review, and for "
                f"{service} it is what turns a password spray into a compromise."
            ),
            remediation=(
                f"Restrict port {port} to a management VPN, a bastion host, or a known office range "
                "using `-s <cidr>`. If it must stay public, add a rate limit and alerting first."
            ),
            port=port,
            service=service,
            rules=[r.raw for r in rules[:3]],
        )

    if any(
        rule.dport in ("-", "any") and rule.is_world_inbound and not rule.is_stateful and not rule.is_loopback
        for rule in ruleset.rules
    ):
        report.add(
            check="fw.wildcard-accept",
            title="A rule accepts all ports and all sources",
            severity="critical",
            detail=(
                "At least one accept rule has no port restriction. This exposes every listening "
                "service, including anything bound after the ruleset was written."
            ),
            remediation="Replace wildcard accepts with explicit per-port rules.",
        )

    if not exposed:
        report.add(
            check="fw.no-world-exposed",
            title="No world-reachable ports found in this ruleset",
            severity="info",
            detail="Every accept rule is scoped to a specific source or a specific port.",
            remediation="No action. Confirm this covers all chains and network interfaces.",
        )


def _check_logging(report: Report, ruleset: Ruleset) -> None:
    has_log = any(
        rule.action.startswith("LOG") or "log" in rule.options or "log prefix" in rule.raw.lower()
        for rule in ruleset.rules
    )
    drops = any(rule.action in ("DROP", "REJECT", "drop", "reject") for rule in ruleset.rules)

    if drops and not has_log:
        report.add(
            check="fw.no-logging",
            title="Traffic is dropped without being logged",
            severity="high",
            detail=(
                "The ruleset drops or rejects traffic but logs nothing. When a real attack is "
                "blocked, there will be no record of it, so detection depends on the attacker "
                "moving to a different technique and succeeding."
            ),
            remediation="Add a LOG rule immediately before the drop in each chain, then ship those logs off-host.",
        )
    elif has_log:
        report.add(
            check="fw.logging",
            title="Firewall logging is enabled (good)",
            severity="info",
            detail="Dropped traffic is logged, so blocked attacks leave an audit trail.",
            remediation="Confirm the log is shipped off-host in real time; a local log is lost with the host.",
        )
    else:
        report.add(
            check="fw.no-drops",
            title="No drop or reject rules found",
            severity="info",
            detail="This ruleset only accepts, which suggests the default policy is doing the blocking.",
            remediation="If the default policy is DROP, add explicit logging so blocks are visible.",
        )


def _check_ordering(report: Report, ruleset: Ruleset) -> None:
    """An ACCEPT before the restriction it should sit behind defeats the restriction."""
    problems: list[str] = []
    for chain in {rule.chain for rule in ruleset.rules}:
        chain_rules = [rule for rule in ruleset.rules if rule.chain == chain]
        unrestricted = [
            rule
            for rule in chain_rules
            if rule.action in ("ACCEPT", "accept", "ALLOW")
            and rule.is_world_inbound
            and rule.dport in ("-", "any")
            and not rule.is_stateful
            and not rule.is_loopback
        ]
        restricted = [
            rule
            for rule in chain_rules
            if rule.action in ("DROP", "REJECT", "drop", "reject") and not rule.is_world_inbound
        ]
        for accept in unrestricted:
            later_drops = [rule for rule in restricted if rule.line_no > accept.line_no]
            if later_drops:
                problems.append(
                    f"chain {chain}: world-open ACCEPT at line {accept.line_no} precedes "
                    f"{len(later_drops)} scoped drop rule(s) starting at line {later_drops[0].line_no}"
                )

    if problems:
        report.add(
            check="fw.rule-order",
            title="Rule ordering defeats a narrower rule",
            severity="high",
            detail=(
                "In iptables and nftables, the first matching rule wins. A broad ACCEPT placed above "
                "a specific restriction means the restriction never applies. " + " | ".join(problems[:4])
            ),
            remediation="Reorder so narrow rules are evaluated first, then verify with `iptables -L -n -v` hit counters.",
            problems=problems,
        )
    else:
        report.add(
            check="fw.rule-order-ok",
            title="No rule-ordering contradictions found",
            severity="info",
            detail="Scoped restrictions are not shadowed by a preceding world-open accept.",
            remediation="Re-check after any rule is added; ordering bugs appear whenever ruleset is edited.",
        )


def _check_recent(report: Report, ruleset: Ruleset) -> None:
    uses_recent = any("recent" in rule.raw for rule in ruleset.rules)
    ssh_rules = [
        rule
        for rule in ruleset.rules
        if rule.is_world_inbound and (rule.dport == "22" or rule.options.get("dport") == "22")
    ]

    if uses_recent:
        report.add(
            check="fw.ssh-recent",
            title="SSH is protected by a recent-module rate limit (good)",
            severity="info",
            detail="The `recent` module tracks failed attempts per source and blocks repeats, which is a real control.",
            remediation="Keep it, and make sure the block list is short enough that a real user cannot lock themselves out.",
        )
    elif ssh_rules:
        report.add(
            check="fw.ssh-no-rate-limit",
            title="SSH is world-reachable with no rate limiting",
            severity="high",
            detail=(
                "Port 22 accepts from any source and nothing limits how many attempts a single "
                "source can make. Internet-wide scanning of SSH runs continuously, so an unthrottled "
                "service is being guessed at all day."
            ),
            remediation=(
                "Add a recent-module rule, or restrict port 22 to a VPN/bastion. fail2ban adds a "
                "second layer by reacting to sshd's own logs."
            ),
            rules=[r.raw for r in ssh_rules[:3]],
        )
