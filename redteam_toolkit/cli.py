"""Command line interface.

Design notes:

* Every subcommand has real ``--help`` text, because a tool whose flags are
  only discoverable by reading the source is a tool nobody uses twice.
* ``--json`` prints the machine-readable bundle to stdout and suppresses the
  human output, so ``rtt scan ... --json | jq`` works.
* Exit codes: ``0`` clean, ``1`` findings at or above ``--fail-on``, ``2`` error.
  That makes the tool usable as a CI gate, which is the point of most of these
  checks.
* Network commands share the authorization and scope flags. Offline commands do
  not need them, so they are only registered where they apply.
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .config import (
    DEFAULT_TCP_PORTS,
    DEFAULT_WORDLIST,
    EXIT_ERROR,
    EXIT_FINDINGS,
    EXIT_OK,
    TOOL_NAME,
)
from .guardrails import (
    DEFAULT_SCOPE,
    AuthorizationError,
    BlockedTargetError,
    TargetContext,
    authorize,
    describe_target,
)
from .models import Report, severity_rank
from .modules import (
    attack as attack_mod,
)
from .modules import (
    cve_lookup,
    firewall_audit,
    hash_audit,
    logs,
    password,
    payload,
    phishing,
    scanner,
    ssh_audit,
    tls_audit,
    webscan,
)
from .reporting import Bundle, print_bundle, write_bundle
from .utils import console
from .utils.net import ResolutionError

EPILOG = f"""\
examples:
  # local lab, loopback scope
  {sys.argv[0] or "rtt"} scan --target 127.0.0.1 --i-understand
  {sys.argv[0] or "rtt"} scan --target 127.0.0.1 --ports 22,80,443,8080,3306 -t 0.5

  # full assessment with reports
  {sys.argv[0] or "rtt"} attack --target 127.0.0.1 --i-understand --format html --output reports/

  # offline analysis (no network, no authorization needed)
  {sys.argv[0] or "rtt"} password --check 'P@ssw0rd2024'
  {sys.argv[0] or "rtt"} logs --file /var/log/auth.log
  {sys.argv[0] or "rtt"} hash-audit --file hashes.txt
  {sys.argv[0] or "rtt"} detect --file suspicious.log
  {sys.argv[0] or "rtt"} cve-lookup --product 'Apache HTTP Server' --version 2.4.29

scope:
  network commands default to loopback and RFC1918 space only. Public addresses
  need --allow-public, and metadata/CGNAT/multicast ranges are refused outright.
"""


# --- helpers --------------------------------------------------------------


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json", action="store_true", help="print the machine-readable report to stdout and nothing else"
    )
    parser.add_argument(
        "--format",
        default="text",
        choices=["text", "json", "html", "txt", "all", "none"],
        help="report format to write to disk (default: text, i.e. print only)",
    )
    parser.add_argument(
        "--output", "-o", metavar="DIR", help="directory for written reports (default: reports/)"
    )
    parser.add_argument(
        "--basename",
        metavar="NAME",
        help="filename stem for written reports (default: rtt-<command>-<timestamp>)",
    )
    parser.add_argument(
        "--fail-on",
        default="none",
        choices=["none", "info", "low", "medium", "high", "critical"],
        help="exit 1 when a finding at or above this severity exists (default: none)",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    parser.add_argument("--show-all", action="store_true", help="print every finding, not the first 12")
    parser.add_argument("--quiet", "-q", action="store_true", help="suppress the human-readable summary")


def _add_scope(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("authorization (required for network commands)")
    group.add_argument(
        "--i-understand",
        action="store_true",
        help="confirm you own this target or have written permission to test it (required non-interactively)",
    )
    group.add_argument(
        "--allow-public", action="store_true", help="permit scanning public internet addresses"
    )
    group.add_argument(
        "--scope",
        action="append",
        metavar="CIDR",
        help="additional permitted range; repeatable. Default: loopback plus RFC1918.",
    )
    group.add_argument("-y", "--yes", action="store_true", help="skip the interactive authorization prompt")


def _stdin_lines() -> list[str]:
    if sys.stdin.isatty():
        return []
    return [line.rstrip("\n") for line in sys.stdin]


# --- command implementations ---------------------------------------------


def cmd_scan(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="scan", command_line=" ".join(sys.argv[1:]))
    ctx = _authorize(args, color, scope_required=True)
    for line in describe_target(args.target):
        console.info(line, color=color)
    report = scanner.scan(
        args.target,
        ctx.address,
        ports=args.ports,
        timeout=args.timeout,
        workers=args.workers,
        grab_banners=not args.no_banners,
    )
    bundle.add(report)

    if not args.no_cve:
        observations = cve_lookup.from_scan_report(report)
        if observations:
            bundle.add(cve_lookup.lookup_report(observations, source=f"{args.target} (scan)"))
    return bundle


def cmd_webscan(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="webscan", command_line=" ".join(sys.argv[1:]))
    url = args.url
    host = _url_host(url)
    if not host:
        console.error(f"could not read a host from {url!r}", color=color)
        raise AuthorizationError(f"no host in {url!r}")

    ctx = _authorize(args, color, target=host, scope_required=True)
    if ctx.address != host:
        # Send traffic to the address the gate just validated rather than
        # re-resolving the name, so the check and the request agree.
        url = url.replace(host, ctx.address, 1)
    console.info(f"authorized for {ctx.label} (scope: {ctx.scope})", color=color)

    report = webscan.scan(
        url,
        timeout=args.timeout,
        verify_tls=not args.no_verify_tls,
        follow_redirects=not args.no_redirects,
        check_paths=not args.no_paths,
        check_methods=not args.no_methods,
        reflect_check=args.reflect,
        workers=args.workers,
    )
    bundle.add(report)
    return bundle


def cmd_tls(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="tls", command_line=" ".join(sys.argv[1:]))
    ctx = _authorize(args, color, scope_required=True)
    report = tls_audit.audit(
        ctx.address,
        args.port,
        sni=args.target if not args.target.replace(".", "").isdigit() else None,
        timeout=args.timeout,
        verify=not args.no_verify_tls,
    )
    bundle.add(report)
    if args.matrix:
        matrix = tls_audit.protocol_support_matrix(ctx.address, args.port)
        report.data["protocol_matrix"] = matrix
        console.info(f"protocol support: {matrix}", color=color)
        for label, supported in matrix.items():
            if supported and label in ("TLS 1.0", "TLS 1.1", "SSL 3.0"):
                report.add(
                    check="tls.supports-deprecated",
                    title=f"Server still accepts {label}",
                    severity="high",
                    detail=f"The server completed a {label} handshake when that protocol was offered in isolation.",
                    remediation="Set the server minimum to TLS 1.2 and re-test.",
                    protocol=label,
                )
    return bundle


def cmd_ssh(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="ssh", command_line=" ".join(sys.argv[1:]))

    if args.config:
        bundle.add(ssh_audit.audit_config(args.config, follow_includes=not args.no_includes))
        return bundle

    ctx = _authorize(args, color, scope_required=True)
    report = ssh_audit.audit_live(args.target, ctx.address, args.port, timeout=args.timeout)
    bundle.add(report)

    if args.config_remote and report.data.get("connected"):
        console.info("note: --config-remote needs a copy of sshd_config; fetch it first", color=color)
    return bundle


def cmd_password(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="password", command_line=" ".join(sys.argv[1:]))

    # An explicit --wordlist always means "estimate the cost of exhausting this
    # combo list", including when it happens to be the default path. The flag
    # has no other meaning on this command, so the file's existence is the only
    # thing that should decide.
    if args.wordlist and Path(args.wordlist).is_file():
        bundle.add(password.combo_estimate(args.wordlist))
        return bundle

    if args.wordlist:
        console.error(f"wordlist not found: {args.wordlist}", color=color)
        raise SystemExit(EXIT_ERROR)

    candidates: list[str] = []
    if args.check is not None:
        candidates.append(args.check)
    if args.file:
        try:
            candidates.extend(
                line.strip()
                for line in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines()
                if line.strip()
            )
        except OSError as exc:
            console.error(f"cannot read {args.file}: {exc}", color=color)
    if not candidates:
        candidates.extend(_stdin_lines())

    if not candidates:
        console.error("nothing to check. use --check, --file, or pipe passwords on stdin.", color=color)
        raise SystemExit(EXIT_ERROR)

    wordlists = [args.dictionary] if args.dictionary else None
    user_inputs = [args.user] if args.user else ()

    if len(candidates) == 1 and not args.json:
        report = password.check(candidates[0], wordlists, user_inputs, on_result=password.describe)
        bundle.add(report)
        return bundle

    bundle.add(password.check_many(candidates, wordlists, user_inputs))
    return bundle


def cmd_hash_audit(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="hash-audit", command_line=" ".join(sys.argv[1:]))

    hashes: list[str] | None = None
    if not args.file and not args.hash:
        hashes = _stdin_lines() or None

    if not args.file and not args.hash and not hashes:
        console.error("provide --file <dump>, --hash <value>, or pipe hashes on stdin.", color=color)
        raise SystemExit(EXIT_ERROR)

    bundle.add(
        hash_audit.audit(
            path=args.file,
            hashes=hashes,
            single=args.hash,
            total_passwords=args.total,
        )
    )
    return bundle


def cmd_logs(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="logs", command_line=" ".join(sys.argv[1:]))
    if not args.file:
        console.error("provide --file <path to auth log>.", color=color)
        raise SystemExit(EXIT_ERROR)

    report = logs.analyze(
        args.file,
        threshold=args.threshold,
        window_seconds=args.window,
        spray_threshold=args.spray,
    )
    bundle.add(report)

    if args.detect_rules:
        console.header("Detection rule pass", "applying the rule catalogue to the same file", color=color)
        try:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            console.error(f"cannot read {args.file}: {exc}", color=color)
        else:
            bundle.add(payload.detect(text, source=args.file))
    return bundle


def cmd_firewall(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="firewall", command_line=" ".join(sys.argv[1:]))
    if not args.file:
        console.error("provide --file <iptables-save / nft / ufw / firewall-cmd output>.", color=color)
        raise SystemExit(EXIT_ERROR)
    bundle.add(firewall_audit.audit(args.file))
    return bundle


def cmd_phishing(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="phishing", command_line=" ".join(sys.argv[1:]))

    if args.directory:
        paths = sorted(
            p for p in Path(args.directory).iterdir() if p.suffix.lower() in (".eml", ".msg", ".txt")
        )
        if not paths:
            console.error(f"no .eml/.msg/.txt files in {args.directory}", color=color)
            raise SystemExit(EXIT_ERROR)
        bundle.add(phishing.analyse_many(paths))
        return bundle

    if args.stdin:
        bundle.add(phishing.analyse("(stdin)", raw_text=sys.stdin.read()))
        return bundle

    if not args.file:
        console.error("provide --file <message.eml>, --directory <dir>, or --stdin.", color=color)
        raise SystemExit(EXIT_ERROR)
    bundle.add(phishing.analyse(args.file))
    return bundle


def cmd_detect(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="detect", command_line=" ".join(sys.argv[1:]))

    if args.rules:
        bundle.add(payload.build_rules_report())
        return bundle

    extra: list[payload.Rule] = []
    if args.extra_rules:
        try:
            extra = payload.parse_extra_rules(args.extra_rules)
        except (OSError, ValueError) as exc:
            console.error(f"bad rule file: {exc}", color=color)
            raise SystemExit(EXIT_ERROR) from exc

    if args.file:
        try:
            text = Path(args.file).read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            console.error(f"cannot read {args.file}: {exc}", color=color)
            raise SystemExit(EXIT_ERROR) from exc
    else:
        text = "\n".join(_stdin_lines())

    if not text.strip():
        console.error("nothing to analyse. use --file, --rules, or pipe text on stdin.", color=color)
        raise SystemExit(EXIT_ERROR)

    report = payload.detect(text, source=args.file or "(stdin)", extra_rules=extra)
    bundle.add(report)

    if extra:
        merged = sorted({*payload.RULES, *extra}, key=lambda r: r.rule_id)
        matched = report.data.get("rules_hit", [])
        report.data["custom_rules_loaded"] = len(extra)
        report.data["rules_evaluated"] = len(merged)
        console.info(
            f"loaded {len(extra)} custom rule(s); {len(matched)} rule(s) matched in total", color=color
        )
    return bundle


def cmd_cve(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="cve-lookup", command_line=" ".join(sys.argv[1:]))

    if args.list:
        report = Report(module="cve_lookup", target="(catalogue)")
        names = list(cve_lookup.products_in_db(args.db))
        report.data["products"] = names
        report.data["product_count"] = len(names)
        database = cve_lookup.load_database(args.db)
        report.data["cves_in_db"] = sum(len(e.get("cves", [])) for e in database.get("products", {}).values())
        console.header("Products in the offline CVE database", color=color)
        console.kv("count", str(len(names)), color=color)
        console.table(["product", "cves"], _product_cve_table(database), color=color)
        bundle.add(report)
        return bundle

    observations: list[tuple[str, str]] = []
    if args.product:
        observations.append((args.product, args.version or ""))
    if args.file:
        for raw in Path(args.file).read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            product, _, version = line.rpartition(" ")
            observations.append((product or line, version))

    if not observations:
        console.error("provide --product and --version, or --file with 'product version' lines.", color=color)
        raise SystemExit(EXIT_ERROR)

    bundle.add(cve_lookup.lookup_report(observations, source=args.file or "cli", db_path=args.db))
    return bundle


def _product_cve_table(database: dict) -> list[list[str]]:
    return [
        [name, str(len(entry.get("cves", [])))]
        for name, entry in sorted(database.get("products", {}).items())
    ]


def cmd_attack(args: argparse.Namespace, color: bool) -> Bundle:
    bundle = Bundle(command="attack", command_line=" ".join(sys.argv[1:]))
    ctx = _authorize(args, color, scope_required=True)

    assessment = attack_mod.run(
        args.target,
        ctx.address,
        ports=args.ports,
        wordlist=args.wordlist,
        timeout=args.timeout,
        workers=args.workers,
        http_timeout=args.http_timeout,
        verify_tls=not args.no_verify_tls,
        check_paths=not args.no_paths,
        cve_db=args.db,
        on_progress=lambda stage, message: console.info(f"[{stage}] {message}", color=color),
    )
    for report in assessment.bundle.reports:
        bundle.add(report)

    console.header(
        "Stage summary", f"{len(assessment.stages)} stage(s) in {assessment.seconds:.1f}s", color=color
    )
    console.table(
        ["stage", "status", "findings", "time", "summary"],
        [[s.name, s.status, s.findings, f"{s.seconds:.2f}s", s.summary] for s in assessment.stages],
        color=color,
    )
    return bundle


# --- plumbing -------------------------------------------------------------


def _authorize(
    args: argparse.Namespace,
    color: bool,
    target: str | None = None,
    scope_required: bool = False,
) -> TargetContext:
    """Run the authorization gate for a network command.

    ``target`` defaults to ``--target``; commands keyed on ``--url`` pass the
    host component of the URL instead.
    """
    host = target if target is not None else getattr(args, "target", None)
    if not host:
        console.error("no target to authorize. pass --target or --url.", color=color)
        raise AuthorizationError("no target supplied")

    scope = DEFAULT_SCOPE
    extra = getattr(args, "scope", None)
    if extra:
        scope = tuple(extra)

    ctx = authorize(
        host,
        allow_public=getattr(args, "allow_public", False),
        scope=scope,
        i_understand=getattr(args, "i_understand", False),
        assume_yes=getattr(args, "yes", False),
        color=color,
    )
    if scope_required:
        console.info(f"authorized for {ctx.label} (scope: {ctx.scope})", color=color)
    return ctx


def _url_host(url: str) -> str | None:
    """Extract the host from a URL, tolerating a missing scheme."""
    from urllib.parse import urlparse

    candidate = url if "//" in url else f"//{url}"
    try:
        return urlparse(candidate).hostname
    except ValueError:
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rtt",
        description=f"{TOOL_NAME} v{__version__}: educational security assessment toolkit",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {__version__}")
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # --- network commands ---
    scan = subparsers.add_parser(
        "scan",
        help="TCP port scan with service fingerprinting and banner capture",
        description="Scan TCP ports, identify services, grab banners, and map versions to known CVEs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    scan.add_argument("--target", "-T", required=True, help="hostname or IP address")
    scan.add_argument(
        "--ports",
        "-p",
        metavar="SPEC",
        help=f"port list or range, e.g. 22,80,8000-8010. Default: {len(DEFAULT_TCP_PORTS)} common ports",
    )
    scan.add_argument("--timeout", "-t", type=float, default=1.0, help="per-port connect timeout in seconds")
    scan.add_argument("--workers", "-w", type=int, default=64, help="concurrent connections")
    scan.add_argument("--no-banners", action="store_true", help="do not read service banners")
    scan.add_argument("--no-cve", action="store_true", help="skip the CVE lookup stage")
    _add_scope(scan)
    _add_common(scan)
    scan.set_defaults(func=cmd_scan)

    web = subparsers.add_parser(
        "webscan",
        aliases=["web"],
        help="HTTP/HTTPS configuration scanner",
        description=(
            "Read-only HTTP configuration review: security headers, leaky banners, cookie "
            "attributes, HTTP methods, and accidentally-published files."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    web.add_argument("--url", "-u", required=True, help="URL or host to scan (scheme is inferred if omitted)")
    web.add_argument("--timeout", "-t", type=float, default=10.0, help="request timeout in seconds")
    web.add_argument("--no-verify-tls", action="store_true", help="do not verify TLS certificates")
    web.add_argument("--no-redirects", action="store_true", help="do not follow redirects")
    web.add_argument("--no-paths", action="store_true", help="skip the exposed-file path checks")
    web.add_argument("--no-methods", action="store_true", help="skip the HTTP method probe")
    web.add_argument(
        "--reflect",
        action="store_true",
        help="also check whether a harmless marker is reflected in the response (defensive check only)",
    )
    web.add_argument("--workers", "-w", type=int, default=8, help="concurrent path probes")
    _add_scope(web)
    _add_common(web)
    web.set_defaults(func=cmd_webscan)

    tls = subparsers.add_parser(
        "tls",
        help="TLS/SSL configuration and certificate audit",
        description="Check the negotiated protocol, cipher, certificate validity and chain, and compression.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    tls.add_argument("--target", "-T", required=True, help="hostname or IP address")
    tls.add_argument("--port", "-p", type=int, default=443, help="TLS port")
    tls.add_argument("--timeout", "-t", type=float, default=8.0, help="handshake timeout in seconds")
    tls.add_argument("--no-verify-tls", action="store_true", help="do not verify the certificate chain")
    tls.add_argument("--matrix", action="store_true", help="probe every protocol version individually")
    _add_scope(tls)
    _add_common(tls)
    tls.set_defaults(func=cmd_tls)

    ssh = subparsers.add_parser(
        "ssh",
        help="SSH configuration audit (offline) or live posture probe",
        description=(
            "With --config, grade an sshd_config offline. Without it, connect to the target and "
            "read the banner and key-exchange proposal. No authentication is attempted."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ssh.add_argument("--target", "-T", help="hostname or IP address (live probe mode)")
    ssh.add_argument("--config", "-c", metavar="FILE", help="path to sshd_config to audit offline")
    ssh.add_argument("--port", "-p", type=int, default=22, help="SSH port (live probe mode)")
    ssh.add_argument("--timeout", "-t", type=float, default=8.0, help="connection timeout in seconds")
    ssh.add_argument("--no-includes", action="store_true", help="do not follow Include directives")
    ssh.add_argument(
        "--config-remote", action="store_true", help="reserved: fetch sshd_config from the target"
    )
    _add_scope(ssh)
    _add_common(ssh)
    ssh.set_defaults(func=cmd_ssh)

    attack = subparsers.add_parser(
        "attack",
        help="automated end-to-end assessment workflow",
        description=(
            "Run recon, offline credential analysis, web review, TLS audit and prioritisation in "
            "sequence, then write a combined report. The credential stage scores a wordlist "
            "locally; no login attempt is made against the target."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    attack.add_argument("--target", "-T", required=True, help="hostname or IP address")
    attack.add_argument("--ports", "-p", metavar="SPEC", help="port list or range (default: common ports)")
    attack.add_argument(
        "--wordlist",
        metavar="PATH",
        default=DEFAULT_WORDLIST,
        help=f"combo wordlist to score offline (default: {DEFAULT_WORDLIST})",
    )
    attack.add_argument("--timeout", "-t", type=float, default=1.0, help="per-port connect timeout")
    attack.add_argument("--http-timeout", type=float, default=10.0, help="web request timeout")
    attack.add_argument("--workers", "-w", type=int, default=64, help="concurrent connections")
    attack.add_argument("--no-verify-tls", action="store_true", help="do not verify TLS certificates")
    attack.add_argument("--no-paths", action="store_true", help="skip exposed-file path checks")
    attack.add_argument("--db", metavar="FILE", help="CVE database path")
    _add_scope(attack)
    _add_common(attack)
    attack.set_defaults(func=cmd_attack)

    # --- offline commands ---
    pwd = subparsers.add_parser(
        "password",
        help="password strength analysis and wordlist estimation (offline)",
        description=(
            "Score password strength by decomposing the candidate into its cheapest explanatory "
            "pattern, then estimate online and offline crack time. Nothing leaves this machine."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    pwd.add_argument("--check", "-c", metavar="PASSWORD", help="a single password to analyse")
    pwd.add_argument("--file", "-f", metavar="PATH", help="file with one password per line")
    pwd.add_argument("--wordlist", "-w", metavar="PATH", help="combo wordlist to estimate exhaust time for")
    pwd.add_argument("--dictionary", metavar="PATH", help="extra wordlist to use for pattern matching")
    pwd.add_argument(
        "--user", "-u", metavar="NAME", help="username/hostname, treated as predictable material"
    )
    _add_common(pwd)
    pwd.set_defaults(func=cmd_password)

    hashes = subparsers.add_parser(
        "hash-audit",
        help="password hash dump audit (offline)",
        description=(
            "Identify the algorithm behind each stored hash, judge its cost parameters, estimate "
            "crack time, and find reused passwords. Hashes are never cracked or transmitted."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    hashes.add_argument("--file", "-f", metavar="PATH", help="dump file: 'user:hash', hash, or htpasswd")
    hashes.add_argument("--hash", metavar="VALUE", help="a single hash to identify")
    hashes.add_argument(
        "--total", type=int, metavar="N", help="total accounts in the breach, for the aggregate estimate"
    )
    _add_common(hashes)
    hashes.set_defaults(func=cmd_hash_audit)

    logcmd = subparsers.add_parser(
        "logs",
        help="authentication log analysis (offline)",
        description=(
            "Detect brute force, password spraying, distributed attacks and the fail-then-success "
            "sequence that indicates a probable compromise, with per-source and per-account context."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    logcmd.add_argument("--file", "-f", metavar="PATH", help="path to the log file (or - for stdin)")
    logcmd.add_argument(
        "--threshold", "-t", type=int, default=5, help="failures before an address is reported"
    )
    logcmd.add_argument("--window", "-w", type=int, default=60, help="timeline bucket size in seconds")
    logcmd.add_argument("--spray", type=int, default=5, help="distinct accounts before spray is reported")
    logcmd.add_argument("--detect-rules", action="store_true", help="also apply the detection rule catalogue")
    _add_common(logcmd)
    logcmd.set_defaults(func=cmd_logs)

    fw = subparsers.add_parser(
        "firewall",
        help="firewall ruleset audit (offline)",
        description="Parse iptables-save, nft, ufw or firewall-cmd output and grade the policy.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    fw.add_argument("--file", "-f", metavar="PATH", required=True, help="ruleset dump file")
    _add_common(fw)
    fw.set_defaults(func=cmd_firewall)

    phish = subparsers.add_parser(
        "phishing",
        help="email header analysis for phishing triage (offline)",
        description=(
            "Explain SPF/DKIM/DMARC results, detect Reply-To and Return-Path mismatches, "
            "lookalike domains, deceptive links and risky attachments."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    phish.add_argument("--file", "-f", metavar="PATH", help="raw .eml message to analyse")
    phish.add_argument("--directory", "-d", metavar="DIR", help="analyse every message in a directory")
    phish.add_argument("--stdin", action="store_true", help="read a raw message from stdin")
    _add_common(phish)
    phish.set_defaults(func=cmd_phishing)

    detect = subparsers.add_parser(
        "detect",
        aliases=["payload"],
        help="detection rule catalogue and log triage (offline)",
        description=(
            "Apply the rule catalogue to log text and extract indicators. This replaces the "
            "original payload generator: the capability is detection, not attack tooling."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    detect.add_argument("--file", "-f", metavar="PATH", help="log or text file to triage")
    detect.add_argument("--rules", action="store_true", help="print the rule catalogue and exit")
    detect.add_argument(
        "--extra-rules", metavar="PATH", help="additional rules as id|name|severity|regex TSV"
    )
    _add_common(detect)
    detect.set_defaults(func=cmd_detect)

    cve = subparsers.add_parser(
        "cve-lookup",
        help="offline CVE matching for a product version",
        description=(
            "Match a product and version against the bundled offline CVE database. Every match is "
            "a candidate: confirm against the vendor advisory and NVD before acting."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    cve.add_argument("--product", "-p", metavar="NAME", help="product name, e.g. 'Apache HTTP Server'")
    cve.add_argument("--version", "-v", metavar="VER", help="detected version string")
    cve.add_argument("--file", "-f", metavar="PATH", help="file with 'product version' lines")
    cve.add_argument("--db", metavar="PATH", help="alternative CVE database path")
    cve.add_argument("--list", action="store_true", help="list the products in the database")
    _add_common(cve)
    cve.set_defaults(func=cmd_cve)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_ERROR

    color = console.enable_color(False if args.no_color else None)
    # Modules print directly; these two calls make their output honour
    # --no-color and --json without every call site having to thread a flag.
    console.set_color(color)
    console.set_quiet(args.json or args.quiet)

    if not hasattr(args, "func"):
        parser.print_help()
        return EXIT_ERROR

    try:
        bundle = args.func(args, color)
    except AuthorizationError as exc:
        console.error(str(exc), color=color)
        return EXIT_ERROR
    except (ResolutionError, BlockedTargetError) as exc:
        console.error(str(exc), color=color)
        return EXIT_ERROR
    except PermissionError as exc:
        console.error(str(exc), color=color)
        return EXIT_ERROR
    except KeyboardInterrupt:
        console.emit()
        console.error("interrupted", color=color)
        return EXIT_ERROR
    except (OSError, ValueError) as exc:
        console.error(f"{type(exc).__name__}: {exc}", color=color)
        return EXIT_ERROR

    written: list[Path] = []
    if args.format != "none":
        formats = {
            "text": ("txt",),
            "txt": ("txt",),
            "json": ("json",),
            "html": ("html",),
            "all": ("json", "html", "txt"),
        }[args.format]
        try:
            written = write_bundle(bundle, output_dir=args.output, basename=args.basename, formats=formats)
        except OSError as exc:
            console.error(f"could not write report: {exc}", color=color)
            return EXIT_ERROR

    if args.json:
        sys.stdout.write(bundle.to_json() + "\n")
    elif not args.quiet:
        print_bundle(bundle, color=color, show_all=args.show_all)

    if written and not args.json and not args.quiet:
        console.info(f"wrote {len(written)} report file(s):", color=color)
        for path in written:
            console.kv("  ", path, color=color)

    if args.fail_on != "none":
        threshold = severity_rank(args.fail_on)
        if any(severity_rank(f.severity) >= threshold for f in bundle.findings):
            console.warn(
                f"failing: {len(bundle.at_or_above(args.fail_on))} finding(s) at or above {args.fail_on}",
                color=color,
            )
            return EXIT_FINDINGS

    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
