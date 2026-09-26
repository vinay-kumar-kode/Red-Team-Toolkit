"""Authentication log analyser.

The original version of this module counted lines containing the word "failed"
and printed a number, which is not a signal. A count of 200 failures tells you
nothing; 200 failures against one account from one address in 40 seconds tells
you a lot. This version builds the aggregation that makes the number matter:

* per-source failure/success counts, sorted by failures
* per-account failure counts, which separates password spraying (few accounts,
  many attempts each) from brute force (one account, many attempts)
* a timeline, so a burst is visible as a burst
* cross-cutting indicators: success after failure run, success from a new
  address, distributed slow spray, and enumeration-shaped usernames

The parser is format-tolerant: it pulls IP, timestamp, username and outcome
from common syslog, auth.log, sshd, Apache and Nginx shapes, and falls back to
a generic "failed/success" classifier for anything unrecognised.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..models import Report, Timer
from ..utils import console

MAX_LINES = 2_000_000

#: Ordered because the first hit wins, so the most specific pattern goes first.
_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "failed",
        re.compile(
            r"(?P<user>[\w.\-\\$]+(?:\\\\[\w.\-]+)?)\s+from\s+(?P<ip>[\w.:a-fA-F]+)\s+"
            r"(?:port\s+\d+\s+)?(?:failed|invalid|incorrect)",
            re.I,
        ),
    ),
    (
        "failed",
        re.compile(
            r"(?:invalid|illegal|bad) user\s+(?P<user>[\w.\-\\$]+)\s+from\s+(?P<ip>[\w.:a-fA-F]+)", re.I
        ),
    ),
    (
        "failed",
        re.compile(
            r"Failed password for (?:invalid user )?(?P<user>[\w.\-\\$]+) from (?P<ip>[\w.:a-fA-F]+)", re.I
        ),
    ),
    (
        "failed",
        re.compile(
            r"(?:authentication failure|login failure|auth failure).*?"
            r"(?:user|for|username)[\s:=]+(?P<user>[\w.\-\\$]+).*?from\s+(?P<ip>[\w.:a-fA-F]+)",
            re.I,
        ),
    ),
    (
        "failed",
        re.compile(
            r"(?P<user>[\w.\-\\$]+)\s+from\s+(?P<ip>[\w.:a-fA-F]+)\b.*?\b(?:failed|denied|unauthorized|401)\b",
            re.I,
        ),
    ),
    (
        "success",
        re.compile(
            r"(?:Accepted password|Accepted publickey|authentication success|session opened)"
            r".*?(?:for\s+)?(?P<user>[\w.\-\\$]+)\s+from\s+(?P<ip>[\w.:a-fA-F]+)",
            re.I,
        ),
    ),
    (
        "success",
        re.compile(
            r"(?:login|signin|sign-in|logged in|logged-in|authenticated)"
            r"[^.\n]{0,40}?(?:user|as)?[ :=\"]+(?P<user>[\w.\-\\$]+)[^.\n]{0,30}?from\s+(?P<ip>[\w.:a-fA-F]+)",
            re.I,
        ),
    ),
    (
        "success",
        re.compile(
            r"(?:user|username)[\s:=]+(?P<user>[\w.\-\\$]+)[^.\n]{0,30}?from\s+(?P<ip>[\w.:a-fA-F]+)"
            r"[^.\n]{0,30}?\b(?:200|success|ok)\b",
            re.I,
        ),
    ),
    (
        "failed",
        re.compile(
            r"(?:user|username)[\s:=]+(?P<user>[\w.\-\\$]+)[^.\n]{0,30}?from\s+(?P<ip>[\w.:a-fA-F]+)"
            r"[^.\n]{0,30}?\b(?:403|401|400|failed|invalid)\b",
            re.I,
        ),
    ),
)

#: Generic fallbacks: no identity, but the outcome is still counted.
_GENERIC_FAIL = re.compile(
    r"\b(?:failed|failure|invalid|denied|unauthorized|unsuccessful|rejected|401|403)\b", re.I
)
_GENERIC_OK = re.compile(r"\b(?:accepted|success(?:ful)?|logged\s*in|authenticated|granted|200)\b", re.I)

_TIMESTAMP_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\[(?P<ts>\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s[+-]\d{4})?)\]"),
    re.compile(r"^\s*(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"^\s*(?P<ts>\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2})"),
    re.compile(r"(?P<ts>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})"),
    # Classic syslog: "Mar  4 09:00:00" or "Mar 14 09:00:00" (no year).
    re.compile(r"^\s*(?:<\d+>)?\s*(?P<ts>[A-Z][a-z]{2}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2})\b"),
)

#: Extraction of a username from the many shapes log formats use.
_USER_FIELDS: tuple[re.Pattern[str], ...] = (
    re.compile(r'\buser="(?P<user>[^"]+)"'),
    re.compile(r"\bruser=(?P<user>\S+)"),
    re.compile(r"\buser=(?P<user>[^\s,;]+)"),
    re.compile(r'\busername="?(?P<user>[^"\s,;]+)'),
    re.compile(r"\bfor\s+(?:invalid user\s+)?(?P<user>[\w.\-\\$]+)\b"),
    re.compile(r'\b(?:logname|account|login)\s*[:=]\s*"?(?P<user>[\w.\-\\$]+)'),
)

_STRIP_ANSI = re.compile(r"\x1b\[[0-9;]*m")
#: Usernames that are guesses rather than real accounts.
COMMON_USERNAMES = frozenset(
    {
        "admin",
        "administrator",
        "root",
        "test",
        "guest",
        "user",
        "info",
        "oracle",
        "postgres",
        "mysql",
        "ftp",
        "www",
        "web",
        "nobody",
        "operator",
        "backup",
        "sysadmin",
        "dev",
        "jenkins",
        "git",
        "deploy",
        "ubuntu",
        "centos",
        "pi",
        "vagrant",
        "sales",
        "support",
        "service",
    }
)


@dataclass(slots=True)
class Event:
    """One authentication-relevant log line."""

    line_no: int
    outcome: str
    user: str | None
    ip: str | None
    when: datetime | None
    raw: str

    def to_dict(self) -> dict:
        return {
            "line": self.line_no,
            "outcome": self.outcome,
            "user": self.user,
            "ip": self.ip,
            "when": self.when.isoformat() if self.when else None,
        }


@dataclass(slots=True)
class SourceProfile:
    """Aggregate behaviour of one source address."""

    ip: str
    failures: int = 0
    successes: int = 0
    users: Counter = field(default_factory=Counter)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    samples: list[Event] = field(default_factory=list)

    @property
    def attempts(self) -> int:
        return self.failures + self.successes

    @property
    def distinct_users(self) -> int:
        return len(self.users)

    @property
    def span_seconds(self) -> float:
        if not (self.first_seen and self.last_seen):
            return 0.0
        return max(0.0, (self.last_seen - self.first_seen).total_seconds())

    @property
    def rate_per_minute(self) -> float:
        if self.span_seconds <= 0:
            return float(self.attempts)
        return self.attempts / (self.span_seconds / 60.0)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "failures": self.failures,
            "successes": self.successes,
            "attempts": self.attempts,
            "distinct_users": self.distinct_users,
            "top_users": self.users.most_common(5),
            "rate_per_minute": round(self.rate_per_minute, 2),
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }


@dataclass(slots=True)
class AccountProfile:
    """Aggregate failures against one account."""

    user: str
    failures: int = 0
    successes: int = 0
    sources: set = field(default_factory=set)
    failed_then_succeeded: bool = False
    last_event: datetime | None = None

    def to_dict(self) -> dict:
        return {
            "user": self.user,
            "failures": self.failures,
            "successes": self.successes,
            "source_count": len(self.sources),
            "failed_then_succeeded": self.failed_then_succeeded,
        }


def analyze(
    path: str | Path,
    threshold: int = 5,
    window_seconds: int = 60,
    spray_threshold: int = 5,
    on_event: str | None = None,
) -> Report:
    """Analyse an authentication log file and return a populated report."""
    log_path = Path(path)
    report = Report(module="logs", target=str(log_path))

    if not log_path.is_file():
        report.add(
            check="log.missing",
            title="Log file not found",
            severity="low",
            detail=f"{log_path} is not a readable file.",
            remediation="Point --file at the auth log, for example /var/log/auth.log or /var/log/secure.",
        )
        report.data["exists"] = False
        return report

    with Timer(report):
        events = list(_parse(log_path, limit=MAX_LINES))
        analysis = summarise(
            events, threshold=threshold, window_seconds=window_seconds, spray_threshold=spray_threshold
        )

        report.data["file"] = str(log_path)
        report.data["size_bytes"] = log_path.stat().st_size
        report.data["lines_read"] = analysis["lines"]
        report.data["events_parsed"] = len(events)
        report.data["unparsed"] = analysis["unparsed"]
        report.data["outcome_totals"] = analysis["totals"]
        report.data["time_span"] = analysis["span"]
        report.data["sources"] = [s.to_dict() for s in analysis["sources"]]
        report.data["accounts"] = [a.to_dict() for a in analysis["accounts"]]
        report.data["top_accounts"] = analysis["top_accounts"]
        report.data["top_sources"] = [s.ip for s in analysis["sources"][:10]]
        report.data["timeline_buckets"] = analysis["timeline"]
        report.data["unknown_username_attempts"] = analysis["unknown_users"]
        report.data["thresholds"] = {
            "failure_threshold": threshold,
            "window_seconds": window_seconds,
            "spray_threshold": spray_threshold,
        }

        _emit_console(analysis)
        _add_findings(report, analysis, events, threshold, window_seconds, spray_threshold)

    if on_event:
        report.data["event_sink"] = on_event
    return report


def _parse(path: Path, limit: int = MAX_LINES) -> Iterator[Event]:
    try:
        reference = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
    except OSError:
        reference = None
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, raw_line in enumerate(handle, start=1):
            if line_no > limit:
                return
            line = _STRIP_ANSI.sub("", raw_line.rstrip("\n"))
            if not line.strip():
                continue

            when = _extract_timestamp(line, reference)
            outcome, user, ip = _classify(line)

            if outcome is None:
                yield Event(line_no, "other", None, None, when, line[:400])
            else:
                yield Event(line_no, outcome, user, ip, when, line[:400])


def _classify(line: str) -> tuple[str | None, str | None, str | None]:
    for expected, pattern in _PATTERNS:
        match = pattern.search(line)
        if match:
            groups = match.groupdict()
            user = _clean_user(groups.get("user")) or _extract_user(line)
            ip = _clean_ip(groups.get("ip")) or _extract_ip(line)
            if expected == "success" and _GENERIC_FAIL.search(line) and "Accepted" not in line:
                # A line containing both words is ambiguous; trust the explicit failure.
                return "failed", user, ip
            return expected, user, ip

    if _GENERIC_FAIL.search(line):
        return "failed", _extract_user(line), _extract_ip(line)
    if _GENERIC_OK.search(line):
        return "success", _extract_user(line), _extract_ip(line)
    return None, None, None


def _extract_user(line: str) -> str | None:
    for pattern in _USER_FIELDS:
        match = pattern.search(line)
        if match:
            cleaned = _clean_user(match.group("user"))
            if cleaned:
                return cleaned
    return None


_IP_FIELDS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:rhost|client|ip|src|source)=?(?P<ip>[\w.:a-fA-F]+)"),
    re.compile(r"\bfrom\s+(?P<ip>[\w.:a-fA-F]+)"),
    re.compile(r"\bclient:\s*(?P<ip>[\w.:a-fA-F]+)"),
)


def _extract_ip(line: str) -> str | None:
    for pattern in _IP_FIELDS:
        match = pattern.search(line)
        if match:
            cleaned = _clean_ip(match.group("ip"))
            if cleaned:
                return cleaned
    return None


#: Words that appear in auth log lines but are never an account name. A loose
#: user capture will otherwise grab "failed" out of "login failed for bob".
_NOT_A_USER = frozenset(
    {
        "failed",
        "fail",
        "failure",
        "success",
        "successful",
        "accepted",
        "denied",
        "rejected",
        "error",
        "invalid",
        "illegal",
        "bad",
        "auth",
        "authentication",
        "login",
        "logout",
        "password",
        "user",
        "username",
        "from",
        "for",
        "the",
        "and",
        "not",
        "sorry",
        "no",
        "yes",
        "true",
        "false",
        "none",
        "null",
        "unauthorized",
        "closed",
        "open",
        "session",
        "connection",
        "root@",
        "0",
    }
)


def _clean_user(value: str | None) -> str | None:
    if not value:
        return None
    user = value.replace("\\\\", "\\").strip("'\"[]<>,;:")
    if not user or len(user) > 64:
        return None
    if user.lower() in _NOT_A_USER:
        return None
    return user


def _clean_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip("'\"[]<>,")
    if not re.fullmatch(r"[0-9a-fA-F:.]{2,45}", candidate):
        return None
    return candidate


def _extract_timestamp(line: str, reference: datetime | None = None) -> datetime | None:
    """Parse the first timestamp in ``line``.

    Syslog omits the year, so the year is taken from ``reference`` (the log
    file's mtime). If the resulting date lands more than a day in the future the
    year is rolled back, which is what happens when a rotated log is read after
    the new year begins.
    """
    for pattern in _TIMESTAMP_PATTERNS:
        match = pattern.search(line)
        if not match:
            continue
        raw = match.group("ts")

        if _SYSLOG_TS.match(raw):
            for year in _candidate_years(reference):
                try:
                    parsed = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
                except ValueError:
                    continue
                parsed = parsed.replace(tzinfo=timezone.utc)
                if reference is not None and parsed > reference + timedelta(days=1):
                    continue
                return parsed
            continue

        for fmt in (
            "%d/%b/%Y:%H:%M:%S %z",
            "%d/%b/%Y:%H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S",
        ):
            candidate = raw.replace("Z", "+0000").replace(",", ".")
            try:
                parsed = datetime.strptime(candidate, fmt)
            except ValueError:
                continue
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed
    return None


_SYSLOG_TS = re.compile(r"[A-Z][a-z]{2}\s{1,2}\d{1,2}\s+\d{2}:\d{2}:\d{2}$")


def _candidate_years(reference: datetime | None) -> tuple[int, int, int]:
    if reference is None:
        now = datetime.now(timezone.utc)
        return (now.year, now.year - 1, now.year + 1)
    return (reference.year, reference.year - 1, reference.year + 1)


def summarise(
    events: list[Event],
    threshold: int = 5,
    window_seconds: int = 60,
    spray_threshold: int = 5,
) -> dict:
    """Aggregate events into the structures the report needs."""
    sources: dict[str, SourceProfile] = {}
    accounts: dict[str, AccountProfile] = {}
    outcome_totals: Counter = Counter()
    unparsed = 0
    lines = 0
    times: list[datetime] = []

    for event in events:
        lines = max(lines, event.line_no)
        if event.outcome == "other":
            unparsed += 1
            continue

        outcome_totals[event.outcome] += 1
        if event.when:
            times.append(event.when)

        if event.ip:
            profile = sources.setdefault(event.ip, SourceProfile(ip=event.ip))
            if event.outcome == "failed":
                profile.failures += 1
            else:
                profile.successes += 1
            if event.user:
                profile.users[event.user] += 1
            if event.when:
                profile.first_seen = min(filter(None, (profile.first_seen, event.when)), default=event.when)
                profile.last_seen = max(filter(None, (profile.last_seen, event.when)), default=event.when)
            if len(profile.samples) < 3 and event.outcome == "failed":
                profile.samples.append(event)

        if event.user:
            account = accounts.setdefault(event.user, AccountProfile(user=event.user))
            if event.outcome == "failed":
                account.failures += 1
            else:
                # A success recorded after any failure for this account is the
                # sequence that matters: the guesses stopped and a login worked.
                if account.failures:
                    account.failed_then_succeeded = True
                account.successes += 1
            if event.ip:
                account.sources.add(event.ip)
            if event.when:
                account.last_event = max(filter(None, (account.last_event, event.when)), default=event.when)

    ordered_sources = sorted(sources.values(), key=lambda s: (-s.failures, -s.distinct_users))
    ordered_accounts = sorted(accounts.values(), key=lambda a: (-a.failures, a.user))

    return {
        "lines": lines,
        "sources": ordered_sources,
        "accounts": ordered_accounts,
        "totals": dict(outcome_totals),
        "unparsed": unparsed,
        "top_accounts": [a.user for a in ordered_accounts[:10]],
        "unknown_users": sorted({a.user for a in ordered_accounts if a.user in COMMON_USERNAMES}),
        "span": _span(times),
        "timeline": _timeline(events, window_seconds),
        "events": events,
    }


def _span(times: list[datetime]) -> str:
    if not times:
        return "unknown"
    delta = max(times) - min(times)
    return f"{(delta.total_seconds() / 60.0):.1f} minute(s)"


def _timeline(events: list[Event], window_seconds: int) -> list[dict]:
    """Bucket failures into fixed windows so bursts are visible."""
    stamps = sorted(e.when for e in events if e.outcome == "failed" and e.when)
    if not stamps:
        return []
    step = max(1, window_seconds)
    buckets: dict[int, int] = defaultdict(int)
    for stamp in stamps:
        buckets[int(stamp.timestamp()) // step] += 1
    return [
        {
            "window_start": datetime.fromtimestamp(bucket * step, tz=timezone.utc).isoformat(),
            "failures": count,
        }
        for bucket, count in sorted(buckets.items())
    ]


def _emit_console(analysis: dict) -> None:
    color = console.enable_color()
    totals = analysis["totals"]
    console.kv("failures", console.paint(str(totals.get("failed", 0)), "warn", color), color=color)
    console.kv("successes", console.paint(str(totals.get("success", 0)), "ok", color), color=color)
    console.kv("time span", analysis["span"], color=color)
    console.kv("unrelated lines", analysis["unparsed"], color=color)

    if analysis["sources"]:
        console.emit()
        console.kv("top sources by failures", "", color=color)
        console.table(
            ["source", "fail", "ok", "users", "rate/min", "span"],
            [
                [
                    s.ip,
                    s.failures,
                    s.successes,
                    s.distinct_users,
                    f"{s.rate_per_minute:.1f}",
                    f"{s.span_seconds:.0f}s",
                ]
                for s in analysis["sources"][:10]
            ],
            color=color,
        )

    if analysis["accounts"]:
        console.emit()
        console.kv("top accounts by failures", "", color=color)
        console.table(
            ["account", "fail", "ok", "sources", "f->s"],
            [
                [
                    a.user,
                    a.failures,
                    a.successes,
                    len(a.sources),
                    console.paint("YES", "bad", color) if a.failed_then_succeeded else "-",
                ]
                for a in analysis["accounts"][:10]
            ],
            color=color,
        )


def _add_findings(
    report: Report,
    analysis: dict,
    events: list[Event],
    threshold: int,
    window_seconds: int,
    spray_threshold: int,
) -> None:
    sources: list[SourceProfile] = analysis["sources"]
    accounts: list[AccountProfile] = analysis["accounts"]

    for source in sources:
        if source.failures < threshold:
            break
        severity = "high" if source.failures >= threshold * 4 else "medium"
        sample = source.samples[0].raw if source.samples else ""
        report.add(
            check="log.bruteforce-source",
            title=f"{source.ip} generated {source.failures} failed logins",
            severity=severity,
            detail=(
                f"{source.failures} failures and {source.successes} successes from {source.ip} "
                f"across {source.distinct_users} account(s) in {source.span_seconds:.0f}s "
                f"({source.rate_per_minute:.1f} attempts/min). Top targets: "
                f"{', '.join(u for u, _ in source.users.most_common(5))}. "
                f"Example line: {sample[:160]}"
            ),
            remediation=(
                "Block or rate-limit the source, force a password reset for any account it touched, "
                "and confirm whether the throttle that should have stopped it is actually enabled."
            ),
            ip=source.ip,
            failures=source.failures,
            successes=source.successes,
            distinct_users=source.distinct_users,
            rate_per_minute=round(source.rate_per_minute, 2),
        )

    for account in accounts:
        if account.failures < threshold:
            break
        if len(account.sources) > 1 and account.failures >= threshold * 3:
            report.add(
                check="log.distributed-attack",
                title=f"Account '{account.user}' attacked from {len(account.sources)} addresses",
                severity="high",
                detail=(
                    f"{account.failures} failures for '{account.user}' from {len(account.sources)} "
                    "distinct sources, which is the shape of a distributed guessing attempt rather "
                    "than a single noisy client."
                ),
                remediation="Require MFA on this account and alert on the aggregate across source addresses.",
                user=account.user,
                sources=len(account.sources),
            )

    for account in accounts:
        if account.failed_then_succeeded and account.failures >= threshold:
            report.add(
                check="log.compromise-indicator",
                title=f"Successful login for '{account.user}' after {account.failures} failures",
                severity="critical",
                detail=(
                    f"The log shows {account.failures} failed attempts for '{account.user}' followed "
                    f"by a success from {', '.join(sorted(account.sources))}. This is the single "
                    "highest-signal event in an authentication log: either the attacker guessed the "
                    "password, or they already had it and the failures were misdirection."
                ),
                remediation=(
                    "Treat as a probable compromise. Reset the credential, revoke active sessions and "
                    "API tokens, review everything that account touched, and check for persistence."
                ),
                user=account.user,
                failures=account.failures,
            )

    for source in sources:
        if source.failures < threshold * 2 or source.distinct_users < spray_threshold:
            continue
        top_user, top_count = source.users.most_common(1)[0]
        # A spray stays under the per-account lockout threshold, so no single
        # account dominates. That is what separates it from brute force.
        if top_count > max(3, source.distinct_users // 2):
            continue
        report.add(
            check="log.password-spray",
            title=(
                f"Password-spray pattern from {source.ip}: {source.distinct_users} accounts, "
                f"at most {top_count} attempt(s) each"
            ),
            severity="high",
            detail=(
                f"{source.failures} failures from {source.ip} spread across "
                f"{source.distinct_users} distinct account(s) in {source.span_seconds:.0f}s, with no "
                f"account taking more than {top_count} attempt(s) ({top_user} was the most targeted). "
                "This is the shape of password spraying, which is deliberately engineered to stay "
                "below per-account lockout thresholds, so per-account alerting alone will not catch "
                f"it. Accounts touched: {', '.join(u for u, _ in source.users.most_common(12))}"
            ),
            remediation=(
                "Alert on the distinct-account count per source address over a sliding window rather "
                "than per account, and enforce MFA so a sprayed password is not sufficient."
            ),
            ip=source.ip,
            accounts=source.distinct_users,
            failures=source.failures,
            max_per_account=top_count,
        )

    unknown = [a for a in accounts if a.user in COMMON_USERNAMES and a.failures > 0]
    if unknown:
        report.add(
            check="log.account-enumeration",
            title=f"Probing of {len(unknown)} generic service account name(s)",
            severity="medium",
            detail=(
                "Failures against well-known administrative names such as "
                + ", ".join(sorted({a.user for a in unknown})[:12])
                + " indicate an attacker guessing account names as well as passwords."
            ),
            remediation="Rename or disable default administrative accounts; alert on login attempts to them.",
            users=sorted({a.user for a in unknown}),
        )

    timeline = analysis["timeline"]
    if timeline:
        peak = max(timeline, key=lambda bucket: bucket["failures"])
        average = sum(b["failures"] for b in timeline) / len(timeline)
        if average > 0 and peak["failures"] >= max(threshold * 2, average * 3):
            report.add(
                check="log.failure-burst",
                title=f"Failure burst: {peak['failures']} failures in one {window_seconds}s window",
                severity="medium",
                detail=(
                    f"Baseline is {average:.1f} failures per {window_seconds}s window; the peak "
                    f"window beginning {peak['window_start']} reached {peak['failures']}. A burst "
                    "this shape is usually a scripted run rather than a user mistyping."
                ),
                remediation="Correlate the window start with authentication and firewall logs for the source.",
                peak=peak["failures"],
                window_seconds=window_seconds,
            )

    if not sources and not accounts:
        report.add(
            check="log.no-auth-events",
            title="No authentication events were recognised",
            severity="info",
            detail=(
                f"{analysis['unparsed']} line(s) were read but none matched a known authentication "
                "pattern. Either the file is not an auth log, or the format is custom."
            ),
            remediation="Confirm the file is the right one, and check whether authentication events go to a different facility.",
        )
