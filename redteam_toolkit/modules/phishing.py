"""Email header analysis for phishing triage.

Reads a raw ``.eml`` file or a pasted header block and explains what the
authentication results mean and whether the envelope matches the claimed sender.
This is the analysis a mail admin does by hand, automated and made repeatable.

The core judgement: the *From* header is display text and proves nothing. What
counts is whether SPF, DKIM and DMARC pass, whether the visible sender domain
matches the domain that actually authenticated the message, and whether
``Reply-To`` points somewhere else. Those three together catch the large
majority of credential phishing.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from email import message_from_string, policy
from email.header import decode_header, make_header
from email.utils import getaddresses
from pathlib import Path
from typing import Any

from ..models import Report, Timer
from ..utils import console

_AUTH_RESULTS = ("none", "neutral", "pass", "fail", "softfail", "temperror", "permerror", "policy")

#: Domains where a missing SPF record is normal and not itself suspicious.
_CLOUD_DOMAINS = frozenset(
    {
        "google.com",
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "office.com",
        "microsoft.com",
        "yahoo.com",
        "icloud.com",
        "aol.com",
        "protonmail.com",
        "zoho.com",
        "protection.outlook.com",
        "messaging.microsoft.com",
    }
)

#: Top-level domains most heavily abused for phishing, for a soft signal only.
_SUSPICIOUS_TLDS = frozenset(
    {"zip", "mov", "top", "xyz", "click", "link", "gq", "cf", "tk", "ml", "work", "country", "kim", "rest"}
)

_BRAND_LOOKALPARTS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "microsoft": "microsoft.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "facebook": "facebook.com",
    "linkedin": "linkedin.com",
    "instagram": "instagram.com",
    "dropbox": "dropbox.com",
    "docusign": "docusign.net",
    "office365": "microsoft.com",
    "office 365": "microsoft.com",
    "microsoft 365": "microsoft.com",
    "okta": "okta.com",
    "amazonaws": "amazon.com",
    "bank": "",
    "secure": "",
    "verify": "",
    "login": "",
}

_URL_RE = re.compile(r"https?://[^\s<>\"'\)\]]+", re.IGNORECASE)
_IP_URL_RE = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})", re.IGNORECASE)
_AT_RE = re.compile(r"https?://[^\s]*@", re.IGNORECASE)
_DISPLAY_RE = re.compile(r"[\w.+-]+\s*(?:<[^>]+>)?\s*[\(\[]([^)\]]+)[\)\]]", re.IGNORECASE)

_SUSPICIOUS_ATTACHMENT = frozenset(
    {
        ".exe",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jse",
        ".wsf",
        ".hta",
        ".iso",
        ".img",
        ".lnk",
        ".apk",
        ".jar",
        ".msi",
        ".one",
        ".zip",
        ".rar",
        ".7z",
        ".html",
        ".htm",
        ".svg",
    }
)

_RISKY_EXTENSIONS = frozenset(
    {".exe", ".scr", ".ps1", ".js", ".vbs", ".hta", ".iso", ".img", ".lnk", ".msi", ".jar", ".apk"}
)


@dataclass(slots=True)
class HeaderResult:
    """Every header this analysis cares about, normalised."""

    headers: dict[str, str] = field(default_factory=dict)
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    return_path_domain: str = ""
    message_id: str = ""
    date: str = ""
    received_chain: list[str] = field(default_factory=list)
    received_hosts: list[str] = field(default_factory=list)
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""
    auth_results: str = ""
    body_urls: list[str] = field(default_factory=list)
    attachments: list[str] = field(default_factory=list)
    body_text: str = ""

    @property
    def spf_verdict(self) -> str:
        return self._verdict(self.spf)

    @property
    def dkim_verdict(self) -> str:
        return self._verdict(self.dkim)

    @property
    def dmarc_verdict(self) -> str:
        return self._verdict(self.dmarc)

    @staticmethod
    def _verdict(value: str) -> str:
        if not value:
            return "absent"
        for result in _AUTH_RESULTS:
            if value.strip().lower() == result:
                return result
        return value.strip().lower() or "absent"

    def to_dict(self) -> dict[str, Any]:
        return {
            "from": self.from_addr,
            "from_domain": self.from_domain,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "message_id": self.message_id,
            "date": self.date,
            "spf": self.spf or "(absent)",
            "dkim": self.dkim or "(absent)",
            "dmarc": self.dmarc or "(absent)",
            "auth_results": self.auth_results or "(absent)",
            "received_hops": len(self.received_hosts),
            "urls": len(self.body_urls),
            "attachments": self.attachments,
        }


def parse_email(source: str | Path, raw_text: str | None = None) -> HeaderResult:
    """Parse a .eml file or raw header text into a :class:`HeaderResult`."""
    if raw_text is None:
        raw_text = Path(source).read_text(encoding="utf-8", errors="replace")

    message = message_from_string(raw_text, policy=policy.default)
    result = HeaderResult()

    for key, value in message.items():
        name = key.lower()
        decoded = _decode(value)
        result.headers.setdefault(name, decoded)

    result.subject = result.headers.get("subject", "")
    result.from_addr = _first_address(result.headers.get("from", ""))
    result.from_name = _display_name(result.headers.get("from", ""))
    result.from_domain = result.from_addr.rsplit("@", 1)[-1].lower() if "@" in result.from_addr else ""
    result.reply_to = _first_address(result.headers.get("reply-to", ""))
    result.return_path = _first_address(result.headers.get("return-path", ""))
    result.return_path_domain = (
        result.return_path.rsplit("@", 1)[-1].lower() if "@" in result.return_path else ""
    )
    result.message_id = result.headers.get("message-id", "").strip()
    result.date = result.headers.get("date", "")

    received = result.headers.get("received", "")
    if received:
        # A single header may be folded; split on the "from" boundaries instead.
        hops = re.split(r"(?=\bfrom\s)", received)
        result.received_chain = [h.strip() for h in hops if h.strip()]
    for hop in result.received_chain:
        host = re.search(r"\bfrom\s+([^\s;(]+)", hop)
        if host:
            result.received_hosts.append(host.group(1))

    result.auth_results = result.headers.get("authentication-results", "")
    result.spf = _extract_result(result, "spf")
    result.dkim = _extract_result(result, "dkim")
    result.dmarc = _extract_result(result, "dmarc")

    body = _extract_body(message)
    result.body_text = body
    result.body_urls = _extract_urls(body)
    result.attachments = _extract_attachments(message)

    return result


def _decode(value: Any) -> str:
    """Decode RFC 2047 encoded words, which is where the real subject lives."""
    try:
        decoded: str = str(make_header(decode_header(str(value))))
    except (UnicodeDecodeError, LookupError, ValueError, TypeError):
        return str(value)
    return decoded


def _first_address(value: str) -> str:
    addresses = getaddresses([value])
    for _name, addr in addresses:
        if addr:
            return addr.strip().lower()
    return ""


def _display_name(value: str) -> str:
    match = re.match(r'^\s*"?([^"<]*)"?\s*<', value)
    return match.group(1).strip() if match else ""


def _extract_result(result: HeaderResult, scheme: str) -> str:
    """Read one scheme's verdict from Authentication-Results, or fall back to headers."""
    if result.auth_results:
        pattern = rf"\b{scheme}=([a-z]+)"
        found = re.findall(pattern, result.auth_results, re.IGNORECASE)
        if found:
            # A message passes a scheme if any evaluating server passed it.
            order = ("pass", "neutral", "none", "softfail", "fail", "temperror", "permerror", "policy")
            for verdict in order:
                if verdict in found:
                    return verdict
            return str(found[0])

    if scheme == "spf" and "spf" in result.headers:
        return result.headers["spf"]
    if scheme == "dkim":
        signature = result.headers.get("dkim-signature", "")
        return "pass" if signature else ""
    return ""


def _extract_body(message: Any) -> str:
    if not message.is_multipart():
        payload = message.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = message.get_content_charset() or "utf-8"
            return payload.decode(charset, "replace")
        return str(message.get_payload())

    parts: list[str] = []
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_disposition() == "attachment":
            continue
        payload = part.get_payload(decode=True)
        if isinstance(payload, bytes):
            charset = part.get_content_charset() or "utf-8"
            parts.append(payload.decode(charset, "replace"))
    return "\n".join(parts)


def _extract_urls(text: str) -> list[str]:
    out: list[str] = []
    for match in _URL_RE.findall(text or ""):
        cleaned = match.rstrip(".,;:)]}'\"")
        if cleaned not in out:
            out.append(cleaned)
    return out


def _extract_attachments(message: Any) -> list[str]:
    names: list[str] = []
    for part in message.walk():
        disposition = part.get_content_disposition()
        filename = part.get_filename()
        if disposition == "attachment" or filename:
            label = _decode(filename) if filename else (part.get_content_type() or "unknown")
            names.append(label)
    return names


# --- analysis -------------------------------------------------------------


def analyse(source: str | Path, raw_text: str | None = None) -> Report:
    """Analyse an email and return a phishing-triage report."""
    report = Report(module="phishing", target=str(source))

    with Timer(report):
        try:
            email = parse_email(source, raw_text)
        except OSError as exc:
            report.add(
                check="phish.unreadable",
                title="Message could not be read",
                severity="low",
                detail=f"{source}: {exc}",
                remediation="Confirm the path, or pipe the raw message in with --stdin.",
            )
            return report

        report.data.update(email.to_dict())
        report.data["from_name"] = email.from_name
        report.data["reply_to_domain"] = email.reply_to.rsplit("@", 1)[-1] if "@" in email.reply_to else ""
        report.data["received_hosts"] = email.received_hosts[:10]

        _emit_console(email)
        _check_authentication(report, email)
        _check_identity(report, email)
        _check_lookalike(report, email)
        _check_links(report, email)
        _check_attachments(report, email)
        _check_urgency(report, email)

    return report


def _emit_console(email: HeaderResult) -> None:
    color = console.enable_color()
    console.kv(
        "from", f"{email.from_name} <{email.from_addr}>" if email.from_name else email.from_addr, color=color
    )
    console.kv("subject", email.subject, color=color)
    console.kv("date", email.date, color=color)
    if email.reply_to:
        console.kv("reply-to", email.reply_to, color=color)
    if email.return_path:
        console.kv("return-path", email.return_path, color=color)
    console.emit()
    for scheme, verdict in (
        ("spf", email.spf_verdict),
        ("dkim", email.dkim_verdict),
        ("dmarc", email.dmarc_verdict),
    ):
        style = {"pass": "ok", "fail": "bad", "softfail": "warn", "none": "warn", "absent": "dim"}.get(
            verdict, "warn"
        )
        console.kv(f"  {scheme}", console.paint(verdict, style, color), color=color)
    console.kv("  received hops", str(len(email.received_hosts)), color=color)
    if email.body_urls:
        console.kv("  urls in body", str(len(email.body_urls)), color=color)
    if email.attachments:
        console.kv("  attachments", ", ".join(email.attachments), color=color)


def _check_authentication(report: Report, email: HeaderResult) -> None:
    verdicts = {
        "spf": email.spf_verdict,
        "dkim": email.dkim_verdict,
        "dmarc": email.dmarc_verdict,
    }
    failing = [name for name, verdict in verdicts.items() if verdict in ("fail", "softfail", "permerror")]
    absent = [name for name, verdict in verdicts.items() if verdict in ("absent", "none")]

    if email.dmarc_verdict == "pass":
        report.add(
            check="phish.dmarc-pass",
            title="DMARC passed: the message is aligned with an authenticated domain",
            severity="info",
            detail=(
                "DMARC=pass means SPF or DKIM passed and the domain in the From header matches "
                "that authenticated domain. This is the strongest single signal available, and a "
                "pass makes spoofing the sender domain very difficult."
            ),
            remediation="No action on this message. Keep DMARC at p=reject once reporting is clean.",
        )
    elif "dmarc" in failing:
        report.add(
            check="phish.dmarc-fail",
            title=f"DMARC {email.dmarc_verdict}: the sender domain did not authorise this message",
            severity="critical",
            detail=(
                f"DMARC={email.dmarc_verdict} with SPF={email.spf_verdict} and DKIM={email.dkim_verdict}. "
                "The message claims to come from a domain that has not authorised the sending server, "
                "which is the defining technical property of most spoofed and phishing email."
            ),
            remediation=(
                "Treat the From address as unverified. Confirm the request through a known-good "
                "channel before acting, and do not use any link in the message."
            ),
            spf=verdicts["spf"],
            dkim=verdicts["dkim"],
            dmarc=verdicts["dmarc"],
        )
    elif "dmarc" in absent and "fail" in failing:
        report.add(
            check="phish.no-dmarc",
            title="Sender domain has no DMARC policy, and SPF or DKIM failed",
            severity="high",
            detail=(
                f"DMARC is absent and {', '.join(failing)} failed. Without DMARC, receivers are "
                "instructed to fall back to whatever SPF and DKIM say, which is the gap phishing "
                "abuses."
            ),
            remediation="Publish a DMARC record at _dmarc.<domain> starting at p=none, then r=quarantine, then r=reject.",
        )

    if "dkim" in absent and email.from_domain and email.from_domain not in _CLOUD_DOMAINS:
        report.add(
            check="phish.no-dkim",
            title="Message carries no DKIM signature",
            severity="low",
            detail=(
                "Without DKIM, nothing cryptographically ties the message to the claimed domain. "
                "SPF alone only proves the sending IP was authorised, and IPs get recycled."
            ),
            remediation="Senders should sign outbound mail with DKIM.",
        )


def _check_identity(report: Report, email: HeaderResult) -> None:
    from_domain = email.from_domain
    reply_domain = email.reply_to.rsplit("@", 1)[-1] if "@" in email.reply_to else ""
    return_domain = email.return_path_domain

    if reply_domain and from_domain and reply_domain != from_domain:
        severity = "critical" if _looks_unrelated(from_domain, reply_domain) else "high"
        report.add(
            check="phish.reply-to-mismatch",
            title=f"Reply-To points to a different domain than From ({reply_domain} vs {from_domain})",
            severity=severity,
            detail=(
                f"From is {from_domain} but Reply-To is {reply_domain}. Replying to a legitimate "
                "message would go to the attacker's address instead. In a business process email "
                "this is the clearest possible signal of account compromise or spoofing."
            ),
            remediation="Do not reply. Contact the claimed sender on a number or address you already trust.",
            from_domain=from_domain,
            reply_to_domain=reply_domain,
        )
    elif reply_domain and from_domain and reply_domain == from_domain:
        report.add(
            check="phish.reply-to-match",
            title="Reply-To matches the From domain",
            severity="info",
            detail=f"Both point at {from_domain}.",
            remediation="No action on this specific check.",
        )

    # Cloud senders legitimately bounce through a different domain, so the
    # mismatch is only meaningful for an organisation's own domain.
    if return_domain and from_domain and return_domain != from_domain and from_domain not in _CLOUD_DOMAINS:
        report.add(
            check="phish.return-path-mismatch",
            title=f"Return-Path domain ({return_domain}) differs from the visible sender ({from_domain})",
            severity="high",
            detail=(
                f"The envelope sender is {return_domain} while the visible sender is {from_domain}. "
                "Bounces and any automatic reply go to the envelope sender, so a mismatch means "
                "the message was relayed through infrastructure the sender does not control."
            ),
            remediation="Verify with the sender out of band before acting on the request.",
            return_path_domain=return_domain,
            from_domain=from_domain,
        )

    bracketed = _DISPLAY_RE.search(email.headers.get("from", ""))
    if email.from_name and bracketed:
        in_brackets = bracketed.group(1)
        if in_brackets.lower() != from_domain:
            report.add(
                check="phish.display-name-trick",
                title=f"Display name reads '{in_brackets}' but the actual domain is '{from_domain}'",
                severity="high",
                detail=(
                    "The visible part of the sender includes a domain in brackets that does not "
                    "match the address the message actually comes from. This is a deliberate "
                    "attempt to defeat quick reading."
                ),
                remediation="Inspect the full address, not the display name. Verify out of band.",
                claimed=in_brackets,
                actual=from_domain,
            )

    if not email.received_hosts and not email.message_id:
        report.add(
            check="phish.no-received-chain",
            title="Message has neither a Received chain nor a Message-ID",
            severity="high",
            detail=(
                "Every message crossing a mail server picks up Received headers. Their absence "
                "means this did not arrive normally, or was assembled and injected directly."
            ),
            remediation="Treat the message as fabricated and report it for analysis.",
        )


def _looks_unrelated(from_domain: str, other: str) -> bool:
    base_from = from_domain.split(".")[-2] if from_domain.count(".") > 1 else from_domain
    base_other = other.split(".")[-2] if other.count(".") > 1 else other
    return base_from not in other and base_other not in from_domain


def _check_lookalike(report: Report, email: HeaderResult) -> None:
    haystack = f"{email.from_name} {email.subject}".lower()
    domain = email.from_domain

    for brand_part, real_domain in _BRAND_LOOKALPARTS.items():
        if not real_domain or brand_part not in haystack:
            continue
        if domain == real_domain:
            continue
        if real_domain in domain or domain in real_domain:
            continue
        if brand_part in domain.replace(".", "").replace("-", ""):
            report.add(
                check="phish.lookalike-domain",
                title=f"Domain '{domain}' imitates {real_domain}",
                severity="critical",
                detail=(
                    f"The message refers to '{brand_part}' and the sender domain is '{domain}', which "
                    f"is not '{real_domain}'. Substituting a character or adding a prefix is the "
                    "standard way to get a lookalike past both a human reader and a first-glance "
                    "URL check."
                ),
                remediation=f"Verify with {real_domain} through a channel you initiate yourself, never through the message.",
                claimed_brand=real_domain,
                actual_domain=domain,
            )
            return

    # The brand may not appear in the subject at all, so also compare the domain
    # itself against known brands after normalising leet substitutions away.
    squashed = _squeeze_domain(domain)
    for brand_part, real_domain in _BRAND_LOOKALPARTS.items():
        if not real_domain:
            continue
        brand_squashed = _squeeze_domain(brand_part)
        if len(brand_squashed) < 5 or brand_squashed == _squeeze_domain(real_domain):
            continue
        if brand_squashed in squashed and squashed != _squeeze_domain(real_domain):
            report.add(
                check="phish.lookalike-domain",
                title=f"Sender domain '{domain}' mimics {real_domain}",
                severity="critical",
                detail=(
                    f"The sender domain is '{domain}'. After normalising character substitutions it "
                    f"reads as '{squashed}', which contains '{brand_squashed}' but is not "
                    f"'{real_domain}'. This is a lookalike domain: the sender is not the organisation "
                    "it appears to be, and no amount of care at the link level will reveal that."
                ),
                remediation=(
                    f"Assume this message did not come from {real_domain}. Contact them using a "
                    "number or address you already hold, not anything in this message."
                ),
                claimed_brand=real_domain,
                actual_domain=domain,
            )
            return

    tld = domain.rsplit(".", 1)[-1] if "." in domain else ""
    if tld in _SUSPICIOUS_TLDS:
        report.add(
            check="phish.low-reputation-tld",
            title=f"Sender uses .{tld}, a top-level domain heavily used for abuse",
            severity="medium",
            detail=(
                f"The domain '{domain}' ends in .{tld}. These registries are inexpensive, allow "
                "instant registration, and are heavily represented in phishing campaigns. This is a "
                "weak signal on its own, but it compounds the other indicators."
            ),
            remediation="Check the domain's age and registration before treating the sender as genuine.",
            tld=tld,
        )

    display = email.from_name
    if (
        display
        and display.lower() != domain
        and re.match(r"^[a-z0-9.-]+\.[a-z]{2,}$", display.strip().lower())
    ):
        report.add(
            check="phish.from-is-domain",
            title=f"From display name looks like a domain: '{display}'",
            severity="medium",
            detail=(
                f"The display name '{display}' resembles a domain while the actual address is "
                f"{email.from_addr}. Mail clients show the display name by default, so this is "
                "designed to be read before the address is checked."
            ),
            remediation="Expand the address before acting on any request.",
        )


def brand_domain(brand_part: str) -> str:
    return _BRAND_LOOKALPARTS.get(brand_part, real_domain_of(brand_part))


#: Characters phishers substitute for letters when building lookalike domains.
_LOET_DOMAINS = str.maketrans(
    {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g", "-": "", "_": ""}
)


def _squeeze_domain(domain: str) -> str:
    """Normalise a domain for lookalike comparison: lowercase, de-leet, unpunctuated."""
    return domain.lower().replace(".", "").translate(_LOET_DOMAINS)


def real_domain_of(part: str) -> str:
    for key, value in _BRAND_LOOKALPARTS.items():
        if key == part:
            return value or part
    return part


def _check_links(report: Report, email: HeaderResult) -> None:
    urls = email.body_urls
    if not urls:
        return

    ip_urls = [url for url in urls if _IP_URL_RE.search(url)]
    userinfo_urls = [url for url in urls if _AT_RE.search(url)]
    external = [url for url in urls if email.from_domain and email.from_domain not in url and not ip_urls]

    report.data["urls"] = urls[:20]
    report.data["ip_based_urls"] = len(ip_urls)
    report.data["userinfo_urls"] = len(userinfo_urls)
    report.data["external_urls"] = len(external)

    if ip_urls:
        report.add(
            check="phish.ip-url",
            title=f"{len(ip_urls)} link(s) use a bare IP address instead of a domain",
            severity="critical",
            detail=(
                "A legitimate organisation sends links to its own domain. A bare IP address cannot "
                "carry a certificate in the user's name, so the browser will show a warning and the "
                "user cannot verify who they are reaching."
            ),
            remediation="Do not visit the link. Verify the destination out of band.",
            urls=ip_urls[:5],
        )

    if userinfo_urls:
        report.add(
            check="phish.userinfo-url",
            title=f"{len(userinfo_urls)} link(s) embed credentials before the real host",
            severity="critical",
            detail=(
                "A URL of the form https://realbank.com@evil.example/ sends the user to "
                "evil.example while displaying 'realbank.com' in the status bar and address text. "
                "This is the most effective trick in phishing because the hostname does not even "
                "need to be spoofed."
            ),
            remediation="Never enter credentials after following such a link. Close it and navigate independently.",
            urls=userinfo_urls[:5],
        )

    if external:
        domains = sorted({_url_domain(url) for url in external} - {email.from_domain})
        report.add(
            check="phish.external-links",
            title=f"{len(external)} link(s) point to domains other than the sender's",
            severity="medium",
            detail=(
                "Link domains: "
                + ", ".join(d for d in domains if d)
                + f". The sender domain is {email.from_domain or 'unknown'}. A mismatch between who "
                "sends and where the link goes is normal for phishing and unusual for legitimate mail."
            ),
            remediation="Hover over each link and confirm the destination domain is one you expect.",
            domains=[d for d in domains if d][:10],
        )

    if len(urls) == 1:
        report.add(
            check="phish.single-link",
            title="Message contains exactly one link",
            severity="low",
            detail=(
                "A single link, and nothing else, means there is nothing for the reader to compare "
                "it against. Legitimate mail usually references the sender's own site by name."
            ),
            remediation="Navigate to the service by typing the address yourself rather than clicking.",
        )


def _url_domain(url: str) -> str:
    match = re.match(r"https?://(?:[^@/]*@)?([^/:?#]+)", url, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _check_attachments(report: Report, email: HeaderResult) -> None:
    if not email.attachments:
        return

    risky = [name for name in email.attachments if Path(name).suffix.lower() in _RISKY_EXTENSIONS]
    archived = [name for name in email.attachments if Path(name).suffix.lower() in _SUSPICIOUS_ATTACHMENT]
    double_ext = [
        name
        for name in email.attachments
        if re.search(r"\.(?:pdf|docx?|xlsx?|jpg|png|txt)\.(?:exe|scr|js|vbs|hta)$", name, re.IGNORECASE)
    ]

    report.data["attachment_count"] = len(email.attachments)
    report.data["risky_attachments"] = risky
    report.data["double_extensions"] = double_ext

    if double_ext:
        report.add(
            check="phish.double-extension",
            title=f"Attachment hides a second extension: {', '.join(double_ext[:3])}",
            severity="critical",
            detail=(
                "Windows hides everything after the first dot, so 'invoice.pdf.exe' displays as a "
                "PDF. This is the most reliable way to get a user to launch an executable."
            ),
            remediation="Do not open it. If the content is expected, retrieve it through the service's own site.",
            attachments=double_ext,
        )

    if risky:
        report.add(
            check="phish.risky-attachment",
            title=f"{len(risky)} attachment(s) can execute code: {', '.join(risky[:4])}",
            severity="critical",
            detail=(
                "These file types run code when opened or when macros are enabled. Executable "
                "attachments arriving by email have no legitimate business use outside software "
                "distribution that signs its releases."
            ),
            remediation=(
                "Do not open. If the file is expected, verify with the sender and download it from "
                "the vendor directly. Block the sender and report the message."
            ),
            attachments=risky,
        )
    elif archived:
        report.add(
            check="phish.archive-attachment",
            title=f"{len(archived)} archive attachment(s): {', '.join(archived[:4])}",
            severity="medium",
            detail=(
                "Archives hide their contents from mail gateways and from the user. A zip is the "
                "standard wrapper for a second-stage payload."
            ),
            remediation="Do not extract until the sender is verified through another channel.",
            attachments=archived,
        )


_URGENCY = re.compile(
    r"\b(?:urgent|immediately|within \d+ (?:hours?|days?)|act now|final notice|suspended|"
    r"will be (?:closed|locked|terminated)|verify your account|confirm your identity|"
    r"unusual (?:activity|sign-in)|password expires|expire[sd]? today|last warning)\b",
    re.IGNORECASE,
)


def _check_urgency(report: Report, email: HeaderResult) -> None:
    text = f"{email.subject}\n{email.body_text[:4000]}"
    hits = sorted({match.group(0).lower() for match in _URGENCY.finditer(text)})

    if not hits:
        return
    report.data["urgency_phrases"] = hits

    if len(hits) >= 2:
        report.add(
            check="phish.urgency-pressure",
            title=f"{len(hits)} urgency or threat phrases detected",
            severity="high",
            detail=(
                "Phrases found: "
                + ", ".join(f"'{hit}'" for hit in hits[:8])
                + ". Manufactured time pressure is a deliberate cognitive tactic: it pushes the "
                "reader past the verification step that would catch the attack. Urgency combined "
                "with a login link is a reliable phishing pattern."
            ),
            remediation=(
                "Slow down. Any request that must be completed immediately can be verified tomorrow "
                "through the normal process, and a genuine organisation will tolerate the delay."
            ),
            phrases=hits,
        )
    else:
        report.add(
            check="phish.urgency-single",
            title=f"Urgency or threat language present: '{hits[0]}'",
            severity="low",
            detail=(
                f"The message contains '{hits[0]}'. This is also normal in legitimate mail from "
                "billing and security teams, so treat it as context rather than a verdict."
            ),
            remediation="Verify the request through a channel you initiate before acting on it.",
            phrases=hits,
        )


def analyse_many(paths: Iterable[str | Path]) -> Report:
    """Triage a directory of messages and summarise the risky ones."""
    report = Report(module="phishing", target="(batch)")
    from ..models import Timer as _Timer

    with _Timer(report):
        analysed = 0
        risky: list[dict] = []

        for path in paths:
            try:
                email = parse_email(path)
            except OSError:
                continue
            analysed += 1

            single = analyse(path)
            critical_high = [f for f in single.findings if f.severity in ("critical", "high")]
            if critical_high:
                risky.append(
                    {
                        "file": str(path),
                        "from": email.from_addr,
                        "subject": email.subject,
                        "dmarc": email.dmarc_verdict,
                        "findings": [f.check for f in critical_high],
                    }
                )

        report.data["messages_analysed"] = analysed
        report.data["suspicious"] = risky[:50]
        report.data["suspicious_count"] = len(risky)

        if risky:
            report.add(
                check="phish.batch-triage",
                title=f"{len(risky)} of {analysed} message(s) have high or critical indicators",
                severity="high",
                detail=(
                    "Review order: "
                    + "; ".join(
                        f"{item['file']} (from {item['from'] or 'unknown'}, DMARC {item['dmarc']})"
                        for item in risky[:8]
                    )
                ),
                remediation=(
                    "Work the lookalike-domain and Reply-To findings first: those two checks have the "
                    "lowest false-positive rate of everything in this module."
                ),
                count=len(risky),
            )
        else:
            report.add(
                check="phish.batch-clean",
                title=f"No high or critical indicators across {analysed} message(s)",
                severity="info",
                detail="Nothing in this batch tripped the strong signals.",
                remediation="Keep the baseline: re-run when a new campaign arrives to spot the shift.",
                count=analysed,
            )

    return report
