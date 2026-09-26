"""Offline password strength analysis and wordlist-based guessing estimates.

Everything here is local. No password is ever sent anywhere; the module reads a
value (or a file) and reasons about it.

Scoring borrows the shape of zxcvbn: rather than only measuring length and
character classes, it decomposes the candidate into the cheapest pattern that
explains it (dictionary word, keyboard run, date, leet substitution, repeat)
and estimates the work an attacker would spend on that pattern. That is what
makes ``P@ssw0rd2024!`` score as weak despite looking complicated.
"""

from __future__ import annotations

import math
import re
import unicodedata
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from ..config import HASH_RATES, OFFLINE_RATE_HPS, ONLINE_RATE_HPS, SLOW_HASH_RATE_HPS
from ..models import Report, Timer
from ..utils import console
from ..utils.net import expand_wordlist

# --- tunables -------------------------------------------------------------

#: Length above which raw cardinality is never the binding constraint.
MAX_REASONABLE_LENGTH = 32
#: Length beyond which more characters add nothing worth counting.
USEFUL_LENGTH = 20

_SCORE_LABELS = ("very weak", "weak", "fair", "strong", "very strong")

_LEET = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i",
        "|": "l",
        "+": "t",
        "(": "c",
        ")": "c",
        "]": "s",
        "[": "c",
    }
)

_KEYBOARD_ROWS = ("qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890", ")!@#$%^&*(")
_ADJACENT = {
    "q": "wa",
    "w": "qes",
    "e": "wrd",
    "r": "etf",
    "t": "ryg",
    "y": "tuh",
    "u": "yij",
    "i": "uok",
    "o": "ipl",
    "p": "ol",
    "a": "qwsz",
    "s": "awedxz",
    "d": "serfcx",
    "f": "drtgvc",
    "g": "ftyhbv",
    "h": "gyujnb",
    "j": "huikmn",
    "k": "jiolm",
    "l": "kop",
    "z": "asx",
    "x": "zsdc",
    "c": "xdfv",
    "v": "cfgb",
    "b": "vghn",
    "n": "bhjm",
    "m": "njk",
    "1": "2q",
    "2": "13w",
    "3": "24e",
    "4": "35r",
    "5": "46t",
    "6": "57y",
    "7": "68u",
    "8": "79i",
    "9": "80o",
    "0": "9p",
}

#: Baked-in worst offenders so the module is useful with no wordlist present.
BUILTIN_COMMON: frozenset[str] = frozenset(
    {
        "password",
        "pass",
        "password1",
        "password123",
        "password1234",
        "p@ssword",
        "p@ssw0rd",
        "passw0rd",
        "123456",
        "1234567",
        "12345678",
        "123456789",
        "1234567890",
        "123123",
        "111111",
        "000000",
        "qwerty",
        "qwerty123",
        "qwertyuiop",
        "letmein",
        "welcome",
        "welcome1",
        "admin",
        "admin123",
        "administrator",
        "root",
        "toor",
        "guest",
        "login",
        "iloveyou",
        "monkey",
        "dragon",
        "sunshine",
        "abc123",
        "abcd1234",
        "football",
        "baseball",
        "master",
        "shadow",
        "michael",
        "jennifer",
        "superman",
        "batman",
        "trustno1",
        "starwars",
        "freedom",
        "whatever",
        "charlie",
        "hello",
        "secret",
        "changeme",
        "test",
        "test123",
        "test1234",
        "default",
        "temp",
        "temp123",
        "user",
        "server",
        "mysql",
        "oracle",
        "postgres",
        "ftp",
        "ssh",
        "r00t",
        "p4ssw0rd",
        "hunter2",
        "summer",
        "winter",
        "spring",
        "autumn",
        "company",
        "google",
        "facebook",
        "linkedin",
        "myemail",
    }
)

BUILTIN_NAMES: frozenset[str] = frozenset(
    {
        "michael",
        "jennifer",
        "jessica",
        "ashley",
        "david",
        "sarah",
        "daniel",
        "karen",
        "amanda",
        "robert",
        "james",
        "mary",
        "thomas",
        "linda",
        "chris",
        "jason",
        "matthew",
        "nicole",
        "emma",
        "andrew",
        "joshua",
        "kevin",
        "brian",
        "anna",
        "alex",
        "eric",
        "peter",
        "paul",
        "steve",
        "andrea",
        "kate",
        "mike",
        "joe",
        "tom",
        "bill",
        "bob",
        "sam",
        "rachel",
        "victoria",
        "olivia",
    }
)


@dataclass(slots=True)
class Match:
    """One pattern that explains part of the candidate."""

    pattern: str
    token: str
    start: int
    end: int
    guesses: float

    @property
    def length(self) -> int:
        return self.end - self.start


@dataclass(slots=True)
class Assessment:
    """Full result of analysing one password."""

    password: str
    score: int
    label: str
    entropy_bits: float
    raw_entropy_bits: float
    guesses: float
    matches: list[Match] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    online_time: float = 0.0
    offline_time: float = 0.0
    charset_size: int = 0
    mask: str = ""

    @property
    def exposed(self) -> list[str]:
        return [m.token for m in self.matches]


# --- character maths ------------------------------------------------------


def charset_of(password: str) -> set[str]:
    return set(password)


def charset_size(password: str) -> int:
    size = 0
    if any(c.islower() and c.isascii() for c in password):
        size += 26
    if any(c.isupper() and c.isascii() for c in password):
        size += 26
    if any(c.isdigit() and c.isascii() for c in password):
        size += 10
    if any(32 < ord(c) < 127 and not c.isalnum() for c in password):
        size += 33
    non_ascii = {c for c in password if ord(c) >= 128}
    if non_ascii:
        size += len(non_ascii) * 10
    return max(size, 1)


def charset_mask(password: str) -> str:
    mask = ""
    if any(c.islower() and c.isascii() for c in password):
        mask += "l"
    if any(c.isupper() and c.isascii() for c in password):
        mask += "u"
    if any(c.isdigit() and c.isascii() for c in password):
        mask += "d"
    if any(32 < ord(c) < 127 and not c.isalnum() for c in password):
        mask += "s"
    if any(ord(c) >= 128 for c in password):
        mask += "x"
    return mask or "-"


def brute_force_guesses(password: str) -> float:
    """Cardinality estimate: ``size ** length``."""
    usable = min(len(password), USEFUL_LENGTH)
    return float(charset_size(password) ** usable)


# --- pattern detection ----------------------------------------------------


def _sequence_guesses(token: str) -> float:
    length = len(token)
    if length <= 2:
        return 1.0
    steps = "abcdefghijklmnopqrstuvwxyz0123456789"
    lower = token.lower()
    rising = sum(1 for i in range(1, length) if steps.find(lower[i]) - steps.find(lower[i - 1]) == 1)
    falling = sum(1 for i in range(1, length) if steps.find(lower[i]) - steps.find(lower[i - 1]) == -1)
    best = max(rising, falling)
    if best == length - 1:
        return 4.0 * length
    if best > length * 0.6:
        return 20.0 * length
    return 200.0 * length


def _keyboard_guesses(token: str) -> float:
    """Guesses needed to cover ``token`` as a keyboard row or walk.

    A row or a walk is a very small space: there are only a handful of rows and
    each key has at most four neighbours, so the cost is roughly constant in the
    token length rather than growing with it.
    """
    length = len(token)
    if length <= 2:
        return 1.0
    if any(all(c in row for c in token.lower()) for row in _KEYBOARD_ROWS):
        return 10.0  # a contiguous run of one row: "qwerty", "asdf", "7890"
    adjacent = sum(1 for i in range(1, length) if token[i].lower() in _ADJACENT.get(token[i - 1].lower(), ""))
    if adjacent >= length - 1:
        return 30.0  # every step lands on a neighbour
    if adjacent >= max(1, (length - 1) // 2):
        return 100.0  # a looser walk
    return 500.0


def _repeat_guesses(token: str) -> float:
    return len(set(token)) * 3.0


def _date_guesses(token: str) -> float:
    if re.fullmatch(r"(19|20)\d{2}", token):
        return 121.0  # year range
    if re.fullmatch(r"[01]?\d[01]?\d", token):
        return 372.0  # valid day-of-month count
    if re.fullmatch(r"[01]?\d[/-][0-3]?\d[/-](19|20)\d{2}", token):
        return 36525.0  # day * month * year
    return 10_000.0


def _leet_variants(token: str) -> list[str]:
    out = {token.lower()}
    out.add(token.lower().translate(_LEET))
    out.add(token.lower().replace("1", "l").replace("0", "o"))
    return [v for v in out if v]


def find_matches(password: str, dictionary: set[str]) -> list[Match]:
    """Find the cheapest explanatory patterns, left to right, longest first.

    Matches are consumed as they are found, so a twelve-character run of ``a``
    is one repeat pattern rather than a dozen overlapping ones.
    """
    if not password:
        return []

    matches: list[Match] = []
    cursor = 0

    while cursor < len(password):
        found: Match | None = None
        for end in range(len(password), cursor, -1):
            token = password[cursor:end]
            if not token:
                continue
            guess = 0.0
            kind = ""

            if re.fullmatch(r"(.)\1{2,}", token):
                guess, kind = _repeat_guesses(token), "repeat"
            elif re.fullmatch(r"(.)\1+", token):
                kind = ""  # a doubled character adds no structure worth reporting
            elif re.fullmatch(
                r"(19|20)\d{2}|[01]?\d[01]?\d[/-][0-3]?\d[/-](19|20)\d{2}|[01]?\d[01]?\d", token
            ):
                guess, kind = _date_guesses(token), "date"
            else:
                variants = _leet_variants(token)
                hit = next((v for v in variants if v in dictionary), None)
                if hit is not None:
                    guess = max(len(dictionary) ** 0.5 * 2, len(hit))
                    kind = "common-password" if hit in BUILTIN_COMMON else "dictionary"
                elif len(token) >= 3 and _keyboard_guesses(token) < 60:
                    guess, kind = _keyboard_guesses(token), "keyboard"
                elif len(token) >= 3 and _sequence_guesses(token) < 100:
                    guess, kind = _sequence_guesses(token), "sequence"

            if kind:
                found = Match(kind, token, cursor, end, guess)
                break

        if found is None:
            cursor += 1
        else:
            matches.append(found)
            cursor = found.end

    return matches


# --- assembly -------------------------------------------------------------


def redact_token(token: str) -> str:
    """A non-reversible stand-in for a pattern token, safe for a report file."""
    if not token:
        return "(empty)"
    return f"{token[0]}{'*' * (len(token) - 1)}({len(token)} chars)"


def load_dictionary(extra: Sequence[str] | None = None) -> set[str]:
    """Baked-in common passwords plus any wordlist files supplied."""
    words: set[str] = set(BUILTIN_COMMON)
    for path in extra or ():
        file_path = Path(path)
        if not file_path.exists():
            continue
        try:
            for word in expand_wordlist(str(file_path)):
                words.add(word.lower())
                for variant in _leet_variants(word):
                    words.add(variant)
        except OSError:
            continue
    words.update(BUILTIN_NAMES)
    return words


def assess(password: str, dictionary: set[str] | None = None, user_inputs: Sequence[str] = ()) -> Assessment:
    """Score one password and explain the verdict."""
    if password is None or password == "":
        return Assessment(
            "",
            0,
            "empty",
            0.0,
            0.0,
            1.0,
            warnings=["No password was supplied."],
            suggestions=["Supply a password to analyse."],
        )

    dictionary = load_dictionary() if dictionary is None else dictionary
    raw = brute_force_guesses(password)
    matches = find_matches(password, dictionary)

    for user_input in user_inputs:
        token = user_input.strip().lower()
        if len(token) >= 3 and token in password.lower():
            matches.insert(
                0,
                Match(
                    "user-input",
                    token,
                    password.lower().index(token),
                    password.lower().index(token) + len(token),
                    2.0,
                ),
            )

    if matches:
        covered = sum(m.length for m in matches)
        unmatched = len(password) - covered
        sum_guesses = sum(m.guesses for m in matches)
        patterned = sum_guesses * (charset_size(password) ** max(unmatched, 0))
        patterned *= 2.0 ** min(len(matches), 12)  # attacker must also try structural permutations
    else:
        patterned = raw

    # Two attacks are available to the attacker: the pattern attack and the raw
    # exhaustive sweep. The cheaper one wins, which is what caps the score.
    guesses = max(1.0, min(patterned, raw))
    entropy = math.log2(guesses) if guesses > 1 else 0.0
    effective_entropy = entropy

    score = _score_for(guesses, len(password))
    online = guesses / ONLINE_RATE_HPS
    offline = guesses / OFFLINE_RATE_HPS

    assessment = Assessment(
        password=password,
        score=score,
        label=_SCORE_LABELS[score],
        entropy_bits=round(effective_entropy, 1),
        raw_entropy_bits=round(math.log2(raw) if raw > 1 else 0.0, 1),
        guesses=guesses,
        matches=sorted(matches, key=lambda m: (m.start, -m.length)),
        online_time=online,
        offline_time=offline,
        charset_size=charset_size(password),
        mask=charset_mask(password),
    )
    _annotate(assessment)
    return assessment


def raw_entropy(password: str) -> float:
    raw = brute_force_guesses(password)
    return math.log2(raw) if raw > 1 else 0.0


def _score_for(guesses: float, length: int) -> int:
    if length < 8:
        return 0 if guesses < 1e6 else 1
    if guesses < 1e6:
        return 0
    if guesses < 1e8:
        return 1
    if guesses < 1e10:
        return 2
    if guesses < 1e12:
        return 3
    return 4


def _annotate(a: Assessment) -> None:
    kinds = {m.pattern for m in a.matches}
    pwd = a.password

    if "user-input" in kinds:
        a.warnings.append("Contains the account name, host name or other supplied context.")
    if "dictionary" in kinds:
        token = next(m.token for m in a.matches if m.pattern == "dictionary")
        a.warnings.append(f"Contains the dictionary word '{token}' (possibly leet-substituted).")
    if "repeat" in kinds:
        a.warnings.append("Contains a repeated character run such as 'aaa' or '1111'.")
    if "sequence" in kinds:
        a.warnings.append("Contains a character sequence such as 'abc' or '1234'.")
    if "keyboard" in kinds:
        a.warnings.append("Follows a keyboard row or walk such as 'qwerty'.")
    if "date" in kinds:
        a.warnings.append("Contains a year or date, which is a tiny search space.")
    if len(pwd) < 12:
        a.warnings.append(f"Only {len(pwd)} character(s) long; 12 or more is the current baseline.")
    if len(pwd) > 0 and len(pwd) < 8:
        a.warnings.append("Below the 8-character minimum enforced by most policies.")
    if pwd.isdigit():
        a.warnings.append("Digits only, so the search space is 10^length.")
    if pwd.isalpha() and pwd.islower():
        a.warnings.append("Lowercase letters only, so the search space is 26^length.")

    if a.score < 4:
        a.suggestions.append("Use 16 or more characters; length buys far more than symbols.")
    if "dictionary" in kinds or "user-input" in kinds:
        a.suggestions.append("Drop the predictable word entirely instead of decorating it.")
    if a.mask in ("l", "ll", "d", "dd", "u", "uu", "lul", "lud", "ld"):
        a.suggestions.append("Add character variety, though length matters more than class count.")
    if a.score < 3:
        a.suggestions.append("Generate it with a password manager so it is unique per site.")
    a.suggestions.append("Enable multi-factor authentication; it removes the guessing problem entirely.")
    if not a.suggestions:
        a.suggestions.append("No change needed. Store it in a password manager, never in a file.")


# --- formatting -----------------------------------------------------------


def format_duration(seconds: float) -> str:
    if seconds < 1:
        return "instantly"
    if seconds < 60:
        return f"{seconds:.0f} second(s)"
    if seconds < 3600:
        return f"{seconds / 60:.0f} minute(s)"
    if seconds < 86400:
        return f"{seconds / 3600:.0f} hour(s)"
    if seconds < 2_592_000:
        return f"{seconds / 86400:.0f} day(s)"
    if seconds < 31_536_000:
        return f"{seconds / 2_592_000:.0f} month(s)"
    if seconds < 3_153_600_000:
        return f"{seconds / 31_536_000:.0f} year(s)"
    return f"{seconds / 3_153_600_000:.0e} year(s)"


def describe(a: Assessment, color: bool | None = None) -> None:
    console.emit()
    console.kv(
        "password",
        console.paint("*" * len(a.password) if a.password else "(empty)", "dim", color),
        color=color,
    )
    console.kv("length", len(a.password), color=color)
    console.kv("charset", f"size {a.charset_size}  mask {a.mask}", color=color)
    bar_width = 40
    filled = int(bar_width * (a.score + 1) / 5)
    bar = console.paint("#" * filled, ["bad", "high", "medium", "low", "ok"][a.score], color) + console.paint(
        "." * (bar_width - filled), "dim", color
    )
    console.kv("score", f"{a.score}/4  {a.label}  [{bar}]", color=color)
    console.kv("entropy", f"{a.entropy_bits} bits effective  ({a.raw_entropy_bits} raw)", color=color)
    console.kv("guesses", f"{a.guesses:.3g}", color=color)
    console.kv(
        "crack time (online)",
        f"{format_duration(a.online_time)} at {ONLINE_RATE_HPS:g} guesses/s",
        color=color,
    )
    console.kv(
        "crack time (offline)",
        f"{format_duration(a.offline_time)} at {OFFLINE_RATE_HPS:.0e} guesses/s, one GPU",
        color=color,
    )

    if a.matches:
        console.emit()
        console.kv("patterns found", "", color=color)
        console.table(
            ["pattern", "token", "span", "guesses"],
            [
                [m.pattern, console.paint(m.token, "warn", color), f"{m.start}-{m.end}", f"{m.guesses:.3g}"]
                for m in a.matches
            ],
            color=color,
        )

    for warning in a.warnings:
        console.warn(warning, color=color)
    if a.suggestions:
        console.emit()
        for suggestion in a.suggestions:
            console.info(suggestion, color=color)


# --- report wrappers ------------------------------------------------------


def check(
    password: str,
    wordlists: Sequence[str] | None = None,
    user_inputs: Sequence[str] = (),
    on_result: Callable[[Assessment], None] | None = None,
) -> Report:
    """Assess a single password."""
    report = Report(module="password", target="(local analysis)")
    with Timer(report):
        dictionary = load_dictionary(wordlists)
        a = assess(password, dictionary, user_inputs)
        report.data["score"] = a.score
        report.data["label"] = a.label
        report.data["length"] = len(password)
        report.data["entropy_bits"] = a.entropy_bits
        report.data["raw_entropy_bits"] = a.raw_entropy_bits
        report.data["charset_size"] = a.charset_size
        report.data["mask"] = a.mask
        report.data["guesses"] = f"{a.guesses:.3g}"
        report.data["crack_time_online"] = format_duration(a.online_time)
        report.data["crack_time_offline"] = format_duration(a.offline_time)
        # Redacted: a written report is an artefact that gets attached to
        # tickets, so it must not be able to reconstruct the password.
        report.data["patterns"] = [f"{m.pattern}: {redact_token(m.token)}" for m in a.matches]

        if a.score <= 1:
            severity = "critical" if a.score == 0 else "high"
            report.add(
                check="pwd.weak",
                title=f"Password is {a.label} (score {a.score}/4)",
                severity=severity,
                detail=(
                    f"{len(password)} characters, {a.entropy_bits} bits of effective entropy, "
                    f"~{a.guesses:.3g} guesses. An offline attack with one GPU would take about "
                    f"{format_duration(a.offline_time)}; an unthrottled online service about "
                    f"{format_duration(a.online_time)}."
                ),
                remediation="; ".join(a.suggestions),
            )
        elif a.score == 2:
            report.add(
                check="pwd.fair",
                title=f"Password is only fair (score {a.score}/4)",
                severity="medium",
                detail=f"{a.entropy_bits} bits of effective entropy, ~{a.guesses:.3g} guesses.",
                remediation="; ".join(a.suggestions),
            )

        for warning in a.warnings:
            if "dictionary" in warning or "user-input" in warning:
                report.add(
                    check="pwd.pattern",
                    title="Password is built from predictable material",
                    severity="high",
                    detail=_redact_in_text(warning, a),
                    remediation="Replace the predictable component instead of appending symbols to it.",
                )

        if on_result is not None:
            on_result(a)

    return report


def check_many(
    passwords: Iterable[str],
    wordlists: Sequence[str] | None = None,
    user_inputs: Sequence[str] = (),
) -> Report:
    """Assess many passwords, keeping the password itself out of the report data.

    ``user_inputs`` behaves as it does for a single password: each candidate is
    checked for containing the account name, hostname or other known context,
    because "jsmith-Summer2024" is a far weaker password than its character
    count suggests.
    """
    report = Report(module="password", target="(batch analysis)")
    with Timer(report):
        dictionary = load_dictionary(wordlists)
        rows: list[dict] = []
        worst: tuple[int, str] | None = None

        for index, password in enumerate(passwords, start=1):
            a = assess(password, dictionary, user_inputs)
            rows.append(
                {
                    "index": index,
                    "score": a.score,
                    "label": a.label,
                    "length": len(password),
                    "entropy_bits": a.entropy_bits,
                    "offline_crack": format_duration(a.offline_time),
                    "patterns": sorted({m.pattern for m in a.matches}),
                }
            )
            if worst is None or a.score < worst[0]:
                worst = (a.score, f"#{index}")

        report.data["checked"] = len(rows)
        report.data["results"] = rows
        report.data["weakest"] = worst[1] if worst else None
        report.data["by_score"] = {
            label: sum(1 for r in rows if r["label"] == label) for label in _SCORE_LABELS
        }

        named = [r for r in rows if "user-input" in r.get("patterns", [])]
        if named:
            report.add(
                check="pwd.batch-user-input",
                title=f"{len(named)} of {len(rows)} password(s) contain the account name or other supplied context",
                severity="high",
                detail=(
                    "Entries (by position): "
                    + ", ".join(f"#{r['index']}" for r in named[:15])
                    + ". A password built from the account name is recoverable from the username "
                    "alone, so a leaked user list hands over the matching password list with it."
                ),
                remediation="Force a reset on each account and generate the replacement independently of the username.",
                positions=[r["index"] for r in named][:50],
            )

        weak = [r for r in rows if r["score"] <= 1]
        if weak:
            report.add(
                check="pwd.batch-weak",
                title=f"{len(weak)} of {len(rows)} password(s) are very weak",
                severity="critical" if len(weak) * 2 >= len(rows) else "high",
                detail=(
                    "Weak entries (by position): "
                    + ", ".join(f"#{r['index']} ({r['label']}, {r['entropy_bits']} bits)" for r in weak[:15])
                ),
                remediation="Rotate every entry at or below score 1 and store replacements in a password manager.",
            )
        fair = [r for r in rows if r["score"] == 2]
        if fair:
            report.add(
                check="pwd.batch-fair",
                title=f"{len(fair)} of {len(rows)} password(s) are merely fair",
                severity="medium",
                detail="Fair passwords fall to a targeted wordlist attack well within a business day.",
                remediation="Bring them to 16+ characters, or replace them with generated values.",
            )

    return report


def combo_estimate(wordlist_path: str, online_rate: float = ONLINE_RATE_HPS) -> Report:
    """Estimate the cost of exhausting a username:password combo list.

    This never contacts a service. It reads the list, counts the candidates an
    attacker would try, and reports how long that takes against an unthrottled
    and a realistically throttled login endpoint.
    """
    report = Report(module="password", target=wordlist_path)
    with Timer(report):
        try:
            combos = expand_wordlist(wordlist_path)
        except OSError as exc:
            report.add(
                check="pwd.wordlist-missing",
                title="Wordlist could not be read",
                severity="low",
                detail=f"{wordlist_path}: {exc}",
                remediation="Check the path, or pass --wordlist to point at a valid file.",
            )
            return report

        wellformed = [c for c in combos if ":" in c]
        dictionary = load_dictionary()
        weak: list[dict] = []
        for combo in wellformed:
            username, _, secret = combo.partition(":")
            a = assess(secret, dictionary, user_inputs=[username])
            if a.score <= 1:
                weak.append({"username": username, "score": a.score, "entropy_bits": a.entropy_bits})

        report.data["wordlist"] = wordlist_path
        report.data["lines"] = len(combos)
        report.data["wellformed_combos"] = len(wellformed)
        report.data["malformed_lines"] = len(combos) - len(wellformed)
        report.data["online_rate"] = online_rate
        report.data["seconds_unthrottled"] = round(len(combos) / max(online_rate, 0.01), 2)
        report.data["seconds_throttled_10s_per_5"] = round(len(combos) / max(online_rate, 0.01) * 50, 2)
        report.data["weak_passwords"] = weak[:20]
        report.data["weak_password_count"] = len(weak)
        report.data["exhaustion_time_unthrottled"] = format_duration(len(combos) / max(online_rate, 0.01))
        report.data["exhaustion_time_throttled"] = format_duration(len(combos) / max(online_rate, 0.01) * 50)

        if weak:
            report.add(
                check="pwd.combo-weak-passwords",
                title=f"{len(weak)} username(s) in the list use a trivially guessable password",
                severity="critical",
                detail=(
                    "These accounts would fall to the first few hundred guesses of any "
                    "standard combo list: " + ", ".join(sorted({w["username"] for w in weak})[:15])
                ),
                remediation="Force a reset on each account and require 16+ characters with no dictionary component.",
            )

        report.add(
            check="pwd.combo-size",
            title="Combo list is too small to be meaningful",
            severity="medium" if len(combos) < 1000 else "info",
            detail=(
                f"The list holds {len(combos)} candidate(s). Real engagements use 10^7-10^9 "
                "combinations, so a list this size only proves that the obvious passwords "
                "are not in use. It is a useful regression check, not a compromise test."
            ),
            remediation="Pair this with lockout alerting and MFA rather than relying on list size.",
        )

    return report


def _redact_in_text(text: str, assessment: Assessment) -> str:
    """Replace every matched pattern token inside a message with a stand-in."""
    out = text
    for match in assessment.matches:
        if match.token and match.token in out:
            out = out.replace(match.token, redact_token(match.token))
    return out


def rate_for_algorithm(algorithm: str) -> float:
    """Guesses/sec for a stored-hash algorithm. Used by the hash audit module."""
    return HASH_RATES.get(algorithm.lower(), SLOW_HASH_RATE_HPS)


def normalise(password: str) -> str:
    """NFKC-normalise so visually identical passwords score identically."""
    return unicodedata.normalize("NFKC", password)
