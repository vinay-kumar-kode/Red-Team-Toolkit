"""Password-hash audit.

Given a dump in any of the common shapes (``user:hash``, ``hash``, htpasswd,
CSV column), work out what algorithm each entry uses, how expensive that
algorithm is, and what an attacker would get for it. Everything is local: hashes
are never sent anywhere and are never cracked.

The judgement that matters is the cost factor. A SHA-256 hash is fine as a
*primitive* and a disaster as a *password storage* scheme, because GPUs try
billions of SHA-256 candidates per second. bcrypt at cost 12, by contrast, is
deliberately slow.
"""

from __future__ import annotations

import base64
import re
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import HASH_RATES, HASH_SEVERITY, SLOW_HASH_RATE_HPS
from ..models import Report, Timer
from ..utils import console
from .password import format_duration

#: (regex, canonical name) ordered most specific first. The bcrypt/modular-crypt
#: formats are checked before bare hex digests, which would match everything.
_ALGORITHMS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("bcrypt", re.compile(r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{50,60}$")),
    ("bcrypt-sha256", re.compile(r"^\$bcrypt-sha256\$\d+\$[./A-Za-z0-9]{22}\$[./A-Za-z0-9]{31,}$")),
    ("argon2id", re.compile(r"^\$argon2id\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")),
    ("argon2i", re.compile(r"^\$argon2i\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")),
    ("argon2d", re.compile(r"^\$argon2d\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")),
    ("scrypt", re.compile(r"^\$scrypt\$ln=\d+,r=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$")),
    ("yescrypt", re.compile(r"^\$yescrypt\$ln=\d+,r=\d+,p=\d+\$[./A-Za-z0-9=]+\$[A-Za-z0-9+/=]+$")),
    ("pbkdf2-sha256", re.compile(r"^\$pbkdf2-sha256\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]{20,}$")),
    ("pbkdf2-sha512", re.compile(r"^\$pbkdf2-sha512\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]{20,}$")),
    ("md5crypt", re.compile(r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{20,24}$")),
    ("django-bcrypt", re.compile(r"^bcrypt_sha256\$(?P<rounds>\d+)\$(?P<salt>[^$]+)\$(?P<digest>.+)$")),
    ("django", re.compile(r"^(?:pbkdf2_sha256\$|argon2\$|scrypt\$)[\w$]*\d+[\w$:=+/]+$")),
    ("crypt-des", re.compile(r"^[./A-Za-z0-9]{13}$")),
    ("sha1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("md5", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("sha256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("sha384", re.compile(r"^[a-fA-F0-9]{96}$")),
    ("sha512", re.compile(r"^[a-fA-F0-9]{128}$")),
    # Last, and deliberately strict: an all-alphabetic string of 24+ characters is
    # far more likely to be a plaintext password than base64, so requiring a
    # base64-specific character or a digit stops this rule eating plain text.
    ("base64", re.compile(r"^(?=[A-Za-z0-9+/=]*[+/=])[A-Za-z0-9+/]{24,}={0,2}$")),
    (
        "base64",
        re.compile(
            r"^(?=[A-Za-z0-9+/=]*\d)(?=[A-Za-z0-9+/=]*[A-Z])(?=[A-Za-z0-9+/=]*[a-z])[A-Za-z0-9+/]{24,}={0,2}$"
        ),
    ),
)

#: Recommended minimum parameters, per NIST SP 800-63B guidance.
RECOMMENDED: dict[str, str] = {
    "argon2id": "m=19456 (19 MiB), t=2, p=1, or OWASP's m=65536,t=3,p=4 profile",
    "bcrypt": "cost 12 or higher (each +1 doubles the work)",
    "scrypt": "N=2^17, r=8, p=1 (RFC 7914 interactive profile)",
    "pbkdf2": "600,000 iterations for SHA-256 (OWASP 2023)",
    "md5crypt": "do not use: 8-character truncation and MD5, superseded by bcrypt",
    "sha256": "do not use as a password hash at all; use argon2id or bcrypt",
}

_COST_PARAMS = {
    "bcrypt": ("cost", re.compile(r"^\$2[abxy]?\$(\d{2})\$")),
    "argon2id": ("memory+iterations", re.compile(r"m=(\d+),t=(\d+),p=(\d+)")),
    "argon2i": ("memory+iterations", re.compile(r"m=(\d+),t=(\d+),p=(\d+)")),
    "argon2d": ("memory+iterations", re.compile(r"m=(\d+),t=(\d+),p=(\d+)")),
    "scrypt": ("cost params", re.compile(r"ln=(\d+),r=(\d+),p=(\d+)")),
    "pbkdf2-sha256": ("iterations", re.compile(r"^\$pbkdf2-sha256\$(\d+)\$")),
    "pbkdf2-sha512": ("iterations", re.compile(r"^\$pbkdf2-sha512\$(\d+)\$")),
}

#: Salt length in bytes, for judging whether a scheme is actually salted.
_SALT_BYTES = {
    "md5": 0,
    "ntlm": 0,
    "lm": 0,
    "sha1": 0,
    "sha256": 0,
    "sha384": 0,
    "sha512": 0,
    "crypt-des": 8,
    "md5crypt": 8,
    "pbkdf2-sha256": 16,
    "pbkdf2-sha512": 16,
    "bcrypt": 16,
    "bcrypt-sha256": 16,
    "argon2id": 16,
    "argon2i": 16,
    "argon2d": 16,
    "scrypt": 16,
    "yescrypt": 16,
}


@dataclass(slots=True)
class HashEntry:
    """One parsed hash, with everything derived from its format."""

    line_no: int
    identifier: str
    algorithm: str
    digest: str
    cost: str = "-"
    rate: float = SLOW_HASH_RATE_HPS
    crack_seconds: float = 0.0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "line": self.line_no,
            "identifier": self.identifier,
            "algorithm": self.algorithm,
            "cost": self.cost,
            "guesses_per_second": f"{self.rate:.3g}",
            "exhaustive_crack_time": format_duration(self.crack_seconds),
            "note": self.note,
        }


def identify(digest: str) -> tuple[str, str]:
    """Return ``(canonical_algorithm, cost_string)`` for a hash string."""
    digest = digest.strip()
    for name, pattern in _ALGORITHMS:
        match = pattern.match(digest)
        if not match:
            continue
        cost = "-"
        spec = _COST_PARAMS.get(name)
        if spec:
            params = spec[1].search(digest)
            if params:
                cost = ",".join(g for g in params.groups() if g)
        if name == "ntlm" and len(digest) == 32:
            cost = "32 hex, no salt"
        return name, cost
    return "unknown", "-"


def _entry_from_line(line_no: int, line: str) -> HashEntry | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    identifier = "-"
    digest = line

    if ":" in line:
        identifier, _, digest = line.partition(":")
        identifier = identifier.strip() or "-"
        digest = digest.strip()
    elif "\t" in line:
        identifier, _, digest = line.partition("\t")
        identifier = identifier.strip() or "-"
        digest = digest.strip()

    if len(digest) < 8:
        return None

    algorithm, cost = identify(digest)
    rate = HASH_RATES.get(algorithm, SLOW_HASH_RATE_HPS)
    space = _search_space(algorithm, digest)
    crack = space / rate

    note = ""
    if algorithm == "unknown":
        note = "unrecognised format; could be a raw password or a non-standard scheme"
    elif _SALT_BYTES.get(algorithm, 0) == 0 and algorithm not in ("unknown", "base64"):
        note = "unsalted: identical passwords produce identical hashes and can be matched across systems"
    elif algorithm == "crypt-des":
        note = "DES-based crypt(3): 8-character limit and 56-bit effective key length"
    elif algorithm == "base64":
        note = "looks like base64 rather than a password hash; possibly a plaintext password in transit"

    return HashEntry(line_no, identifier, algorithm, digest, cost, rate, crack, note)


def _search_space(algorithm: str, digest: str) -> float:
    """Guessable keyspace for an exhaustive search against one entry."""
    if algorithm in ("lm", "crypt-des"):
        return 26.0**7  # 7 effective characters
    if algorithm in ("md5", "ntlm"):
        return 10.0**11
    if algorithm == "sha1":
        return 10.0**11
    return 10.0**14  # a typical 14-character mixed password


def parse_dump(path: str | Path) -> list[HashEntry]:
    """Parse a hash dump from a file, skipping comments and blanks."""
    entries: list[HashEntry] = []
    with Path(path).open("r", encoding="utf-8", errors="replace") as handle:
        for line_no, line in enumerate(handle, start=1):
            entry = _entry_from_line(line_no, line)
            if entry is not None:
                entries.append(entry)
    return entries


def audit(
    path: str | Path | None = None,
    hashes: Iterable[str] | None = None,
    single: str | None = None,
    total_passwords: int | None = None,
) -> Report:
    """Audit a hash dump, a list of hashes, or one hash."""
    report = Report(module="hash_audit", target=str(path) if path else "(provided hashes)")

    with Timer(report):
        entries: list[HashEntry] = []

        if single:
            entry = _entry_from_line(1, single)
            entries = [entry] if entry else []
        elif path:
            try:
                entries = parse_dump(path)
            except OSError as exc:
                report.add(
                    check="hash.dump-missing",
                    title="Hash dump could not be read",
                    severity="low",
                    detail=f"{path}: {exc}",
                    remediation="Check the path and permissions on the file.",
                )
                return report
        elif hashes is not None:
            for index, line in enumerate(hashes, start=1):
                entry = _entry_from_line(index, line)
                if entry is not None:
                    entries.append(entry)

        if not entries:
            report.add(
                check="hash.empty",
                title="No hash entries to analyse",
                severity="info",
                detail="Nothing was parsed from the input.",
                remediation="Provide --file, --hash, or pipe a dump on stdin.",
            )
            return report

        report.data["entries"] = len(entries)
        report.data["results"] = [entry.to_dict() for entry in entries[:200]]
        report.data["results_truncated"] = len(entries) > 200
        report.data["algorithms"] = {}
        for entry in entries:
            family = _base(entry.algorithm)
            report.data["algorithms"][family] = report.data["algorithms"].get(family, 0) + 1
        report.data["fastest_to_attack"] = (
            min(entries, key=lambda e: e.crack_seconds).algorithm if entries else "-"
        )
        report.data["weakest_crack_time"] = (
            format_duration(min(e.crack_seconds for e in entries)) if entries else "-"
        )
        if total_passwords:
            report.data["assumed_breach_size"] = total_passwords

        _emit_console(entries, total_passwords)
        _add_findings(report, entries, total_passwords)

    return report


def _emit_console(entries: list[HashEntry], total_passwords: int | None) -> None:
    color = console.enable_color()
    console.kv("entries", str(len(entries)), color=color)

    by_algorithm = Counter(entry.algorithm for entry in entries)
    console.emit()
    console.kv("algorithms in use", "", color=color)
    console.table(
        ["algorithm", "count", "severity", "guesses/s", "work factor"],
        [
            [
                algorithm,
                str(count),
                console.paint(
                    HASH_SEVERITY.get(_base(algorithm), "medium"),
                    HASH_SEVERITY.get(_base(algorithm), "medium"),
                    color,
                ),
                "-"
                if _base(algorithm) == "unknown"
                else f"{HASH_RATES.get(_base(algorithm), SLOW_HASH_RATE_HPS):.3g}",
                _describe_cost(algorithm, entries),
            ]
            for algorithm, count in by_algorithm.most_common()
        ],
        color=color,
    )

    fastest = min(entries, key=lambda e: e.crack_seconds)
    console.emit()
    console.kv(
        "fastest to attack", f"{fastest.algorithm} -> {format_duration(fastest.crack_seconds)}", color=color
    )
    if total_passwords:
        console.kv(
            "full dump to crack",
            format_duration(sum(e.crack_seconds for e in entries) / 1e6),
            color=color,
        )
    console.emit()
    console.kv("entries", "", color=color)
    console.table(
        ["line", "identifier", "algorithm", "cost", "exhaustive time"],
        [
            [e.line_no, e.identifier, e.algorithm, e.cost, format_duration(e.crack_seconds)]
            for e in entries[:20]
        ],
        color=color,
    )
    if len(entries) > 20:
        console.info(f"... {len(entries) - 20} more (use --json for the full list)", color=color)


def _base(algorithm: str) -> str:
    """Map variants onto the family used for severity and rate lookups."""
    if algorithm.startswith("argon2"):
        return "argon2"
    if algorithm.startswith("pbkdf2") or algorithm == "django":
        return "pbkdf2"
    if algorithm.startswith("bcrypt") or algorithm == "django-bcrypt":
        return "bcrypt"
    if algorithm == "sha384":
        return "sha384"
    return algorithm


def _describe_cost(algorithm: str, entries: list[HashEntry]) -> str:
    costs = {e.cost for e in entries if e.algorithm == algorithm and e.cost != "-"}
    if costs:
        return ", ".join(sorted(costs))[:40]
    return "-"


def _add_findings(report: Report, entries: list[HashEntry], total_passwords: int | None) -> None:
    by_family: dict[str, list[HashEntry]] = {}
    for entry in entries:
        by_family.setdefault(_base(entry.algorithm), []).append(entry)

    for family, group in by_family.items():
        severity = HASH_SEVERITY.get(family, "medium")
        count = len(group)
        if count == 0:
            continue

        detail_bits = [f"{count} of {len(entries)} entries"]
        if family in ("md5", "ntlm", "lm"):
            detail_bits.append(
                "These are unsalted fast digests. A single consumer GPU sustains billions of "
                "these per second, so the whole dump is recoverable in hours to days, and because "
                "there is no salt the same hash can be matched against every other database that "
                "stored the same password."
            )
        elif family == "sha256":
            detail_bits.append(
                "SHA-256 is a fine general-purpose digest and a poor password hash: it is designed "
                "to be fast, which is exactly wrong for password storage. Use argon2id or bcrypt."
            )
        elif family in ("argon2", "bcrypt", "scrypt", "yescrypt"):
            detail_bits.append(
                f"{family} is a memory-hard or deliberately slow scheme, which is the correct "
                f"choice. Recommended parameters: {RECOMMENDED.get(family, 'see current guidance')}."
            )
        elif family == "crypt-des":
            detail_bits.append(
                "crypt(3) DES hashing truncates at 8 characters and has a 56-bit key. A modern GPU "
                "exhausts the entire keyspace in under a day."
            )
        elif family == "base64":
            detail_bits.append(
                "These entries are not password hashes. If they are credentials in transit, or "
                "passwords encoded before storage, they are effectively plaintext."
            )
        else:
            detail_bits.append("Unrecognised format. Confirm how these are produced before relying on them.")

        report.add(
            check=f"hash.algorithm-{family}",
            title=f"{count} password(s) hashed with {family}",
            severity=severity,
            detail="; ".join(detail_bits),
            remediation=(
                f"Re-hash with {RECOMMENDED.get(family, 'argon2id')} and force a reset on reset, "
                "so the old hashes are not the ones an attacker uses."
            ),
            algorithm=family,
            count=count,
        )

    for family, group in by_family.items():
        if family not in ("bcrypt", "argon2", "scrypt", "yescrypt"):
            continue
        weak_params: list[str] = []
        for entry in group:
            if _params_weak(family, entry.cost):
                weak_params.append(f"{entry.identifier or entry.line_no}({entry.cost})")
        if weak_params:
            report.add(
                check="hash.low-cost-params",
                title=f"{family} configured below recommended cost",
                severity="high",
                detail=(
                    "These entries were produced with parameters weaker than current guidance "
                    f"({RECOMMENDED.get(family, '')}). Entries: {', '.join(weak_params[:10])}."
                ),
                remediation="Raise the work factor and re-hash on next successful login.",
                weak=weak_params[:20],
            )

    duplicates = _find_duplicates(entries)
    if duplicates:
        total_dupes = sum(count - 1 for count in duplicates.values())
        report.add(
            check="hash.reused-passwords",
            title=f"{len(duplicates)} password(s) shared across {total_dupes + len(duplicates)} account(s)",
            severity="high",
            detail=(
                "Identical digests mean identical passwords (there is no salt on the fast hashes, "
                "so this is a true match). A single credential-stuffing list compromises every "
                "account that reused the password. Examples: "
                + ", ".join(
                    f"{_identifier_of(entries, d)} x{count}" for d, count in list(duplicates.items())[:5]
                )
            ),
            remediation="Force a reset on each affected account. Password reuse is the mechanism that turns one breach into many.",
            duplicate_groups=len(duplicates),
        )

    unknown = [e for e in entries if e.algorithm == "unknown"]
    if unknown:
        report.add(
            check="hash.unknown-format",
            title=f"{len(unknown)} entry(ies) are not recognised password hashes",
            severity="medium",
            detail=(
                "Unrecognised entries: "
                + ", ".join(f"line {e.line_no} ({len(e.digest)} chars)" for e in unknown[:8])
                + ". These may be plaintext passwords, custom formats, or a scheme this tool "
                "does not know. If they are plaintext, treat this dump as a live credential list."
            ),
            remediation="Determine how these values are produced. If they are not hashes, rotate the credentials immediately.",
        )

    if total_passwords and entries:
        weakest_rate = max(e.rate for e in entries)
        time_to_crack = (weakest_rate * len(entries)) / 1e9
        report.add(
            check="hash.aggregate-risk",
            title=f"Estimated time to recover the weakest {len(entries)} password(s)",
            severity="critical" if time_to_crack < 86400 else "high",
            detail=(
                f"Using the slowest algorithm present ({weakest_rate:.3g} guesses/s), an offline "
                f"attack on a {total_passwords:,}-entry list where the weakest algorithm applies "
                f"would take roughly {format_duration(weakest_rate * len(entries))}. This assumes a "
                "reasonable password distribution; a targeted wordlist attack is far faster."
            ),
            remediation="Treat the whole dump as compromised. Rotate every credential, then fix the storage scheme.",
        )


def _params_weak(family: str, cost: str) -> bool:
    if cost == "-":
        return True
    try:
        numbers = [int(n) for n in re.findall(r"\d+", cost)]
    except ValueError:
        return False
    if not numbers:
        return True

    if family == "bcrypt":
        return numbers[0] < 12
    if family in ("argon2", "argon2id", "argon2i", "argon2d"):
        memory, iterations = numbers[0], numbers[1] if len(numbers) > 1 else 0
        return memory < 16384 or iterations < 2
    if family == "scrypt":
        return numbers[0] < 17
    if family in ("md5crypt", "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512"):
        return numbers[0] < 600_000
    return False


def _find_duplicates(entries: list[HashEntry]) -> dict[str, int]:
    counter = Counter(e.digest for e in entries)
    return {digest: count for digest, count in counter.items() if count > 1 and len(digest) >= 8}


def _identifier_of(entries: list[HashEntry], digest: str) -> str:
    for entry in entries:
        if entry.digest == digest:
            return entry.identifier
    return "?"


def identify_many(lines: Iterable[str]) -> list[HashEntry]:
    """Convenience wrapper for callers that already hold the lines."""
    out: list[HashEntry] = []
    for index, line in enumerate(lines, start=1):
        entry = _entry_from_line(index, line)
        if entry is not None:
            out.append(entry)
    return out


def b64_word_count(encoded: str) -> int:
    """Rough word count of a base64 string, used for size reporting only."""
    try:
        raw = base64.b64decode(encoded + "=" * (-len(encoded) % 4), validate=False)
    except Exception:
        return 0
    return len(raw)
