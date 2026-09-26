"""Static configuration: service fingerprints, header baselines, severity scales."""

from __future__ import annotations

from typing import Final

TOOL_NAME: Final = "Red Team Toolkit"
VERSION: Final = "2.0.0"

#: Exit codes. 0 = clean, 1 = findings at/above --fail-on, 2 = usage/runtime error.
EXIT_OK: Final = 0
EXIT_FINDINGS: Final = 1
EXIT_ERROR: Final = 2

SEVERITY_ORDER: Final = ("info", "low", "medium", "high", "critical")

#: Ports probed by ``scan`` unless ``--ports`` is given. Lab-friendly set.
DEFAULT_TCP_PORTS: Final = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    443,
    445,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8088,
    8443,
    8888,
    9090,
    9200,
    27017,
)

COMMON_PORTS: Final = (21, 22, 80, 443)

#: port -> (service name, default banner probe, expected version hint regex)
TCP_SERVICES: Final[dict[int, tuple[str, bool, str]]] = {
    21: ("FTP", True, r"(\d+\.\d+)"),
    22: ("SSH", True, r"OpenSSH[_ -](\d+\.\d+(?:p\d+)?)"),
    23: ("Telnet", True, r""),
    25: ("SMTP", True, r""),
    53: ("DNS", False, r""),
    80: ("HTTP", True, r""),
    110: ("POP3", True, r""),
    111: ("rpcbind", False, r""),
    135: ("MSRPC", False, r""),
    139: ("NetBIOS", False, r""),
    143: ("IMAP", True, r""),
    443: ("HTTPS", False, r""),
    445: ("SMB", True, r"(\d+\.\d+)"),
    993: ("IMAPS", False, r""),
    995: ("POP3S", False, r""),
    1433: ("MSSQL", False, r""),
    1521: ("Oracle", False, r""),
    2049: ("NFS", False, r""),
    3306: ("MySQL", True, r"([\d.]+)"),
    3389: ("RDP", True, r""),
    5432: ("PostgreSQL", False, r""),
    5900: ("VNC", True, r"(RFB\s*\d+\.\d+)"),
    6379: ("Redis", True, r"redis[\s-]?([\d.]+)"),
    8000: ("HTTP-alt", False, r""),
    8080: ("HTTP-proxy", False, r""),
    8088: ("HTTP-alt", False, r""),
    8443: ("HTTPS-alt", False, r""),
    8888: ("HTTP-alt", False, r""),
    9090: ("HTTP-alt", False, r""),
    9200: ("Elasticsearch", True, r"(\d+\.\d+\.\d+)"),
    27017: ("MongoDB", False, r""),
}

#: Services reachable with a username only, no password. Always a finding.
ANONYMOUS_SERVICES: Final = frozenset({"FTP", "SMB", "Redis", "MongoDB", "NFS", "rpcbind"})

#: Services that speak a line-based protocol where a credential pair is meaningful.
CREDENTIAL_SERVICES: Final = frozenset(
    {"FTP", "SSH", "Telnet", "SMTP", "POP3", "IMAP", "MSSQL", "MySQL", "PostgreSQL", "VNC"}
)

#: Services commonly abused for webshells / callback channels, by detected service name.
RISKY_EXPOSURE: Final[dict[str, str]] = {
    "Telnet": "Cleartext remote administration. Disable it; use SSH.",
    "FTP": "Credentials cross the wire in cleartext. Move to SFTP.",
    "rlogin": "Inherently cleartext. Remove.",
    "VNC": "Often deployed with weak or no authentication. Restrict to VPN.",
    "Redis": "Frequently unauthenticated by default and RCE-able via config/SLAVEOF.",
    "MongoDB": "Frequently unauthenticated by default; exposes entire database.",
    "SMB": "SMBv1 and guest access are common paths to lateral movement.",
    "rpcbind": "Leaks mount/export tables and aids NFS enumeration.",
    "NFS": "World-exported NFS is a direct data-exposure path.",
    "MSSQL": "Often exposed to the internet with sa or weak service accounts.",
    "Elasticsearch": "Default installs have no authentication enabled.",
    "MySQL": "Direct database exposure invites credential attacks.",
    "PostgreSQL": "Direct database exposure invites credential attacks.",
}

#: header -> (why it matters, severity if missing)
HEADER_BASELINE: Final[dict[str, tuple[str, str]]] = {
    "Strict-Transport-Security": ("Forces HTTPS and blocks SSL-strip downgrade.", "medium"),
    "Content-Security-Policy": (
        "Primary XSS mitigation; without it the browser executes injected script.",
        "high",
    ),
    "X-Content-Type-Options": ("Stops MIME sniffing turning a benign file into executable script.", "low"),
    "X-Frame-Options": ("Clickjacking protection; CSP frame-ancestors is the modern control.", "medium"),
    "Referrer-Policy": ("Stops full URLs leaking to third parties via the Referer header.", "low"),
    "Permissions-Policy": ("Restricts access to camera, mic, geolocation and similar features.", "info"),
    "Cross-Origin-Opener-Policy": ("Isolates browsing context against tabnabbing.", "info"),
    "Cross-Origin-Resource-Policy": ("Blocks cross-origin reads of your resources.", "info"),
}

#: Informational headers that should NOT be present.
LEAKY_HEADERS: Final[dict[str, str]] = {
    "Server": "Reveals server software and version to attackers.",
    "X-Powered-By": "Reveals application framework and version.",
    "X-AspNet-Version": "Reveals ASP.NET version.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version.",
    "X-Generator": "Reveals the CMS generator and version.",
    "X-Drupal-Cache": "Reveals Drupal and its cache HIT/DRUPAL7 flags.",
    "X-Runtime": "Reveals Ruby on Rails version.",
}

#: Cookie attributes checked on every Set-Cookie value.
COOKIE_ATTRS: Final[dict[str, str]] = {
    "Secure": "Cookie will not be sent over plain HTTP.",
    "HttpOnly": "Cookie is invisible to JavaScript, blunting XSS session theft.",
    "SameSite": "Limits cross-site request forgery.",
}

#: TLS protocol versions considered acceptable, mapped to a verdict.
TLS_VERSIONS: Final[dict[int, str]] = {
    0x0000: "removed",
    0x0301: "deprecated (TLS 1.0)",
    0x0302: "deprecated (TLS 1.1)",
    0x0303: "acceptable",
    0x0304: "acceptable",
}

#: Cipher names that should never be negotiated.
WEAK_CIPHERS: Final[frozenset[str]] = frozenset(
    {
        "NULL",
        "EXPORT",
        "DES",
        "RC4",
        "RC2",
        "MD5",
        "ANON",
        "IDEA",
    }
)

CERT_PROBLEMS: Final[dict[str, str]] = {
    "expired": "Certificate is expired. Browsers and clients will reject it.",
    "not_yet_valid": "Certificate start date is in the future (clock skew or bad config).",
    "self_signed": "Certificate is self-signed; no public chain of trust.",
    "hostname_mismatch": "Certificate does not cover the requested hostname.",
    "weak_signature": "Certificate uses a broken signature algorithm such as MD5 or SHA-1.",
    "expiring_soon": "Certificate expires within 30 days; renewal is overdue.",
    "long_validity": "Certificate lifetime exceeds 398 days, which public CAs must refuse.",
}

#: Password cracking model. Online guesses/sec with no rate limiting (defensive estimate only).
ONLINE_RATE_HPS: Final = 10.0
OFFLINE_RATE_HPS: Final = 1e11
SLOW_HASH_RATE_HPS: Final = 1e4

HASH_RATES: Final[dict[str, float]] = {
    "md5": 5e10,
    "md4": 1e11,
    "md2": 1e11,
    "ntlm": 5e10,
    "lm": 1e7,
    "sha1": 2e10,
    "sha224": 1e10,
    "sha256": 1e10,
    "sha384": 1e9,
    "sha512": 5e9,
    "bcrypt": 5e2,
    "argon2": 2e2,
    "scrypt": 5e2,
    "pbkdf2": 2e4,
    "yescrypt": 5e2,
    "des": 1e7,
    "3des": 1e7,
    "bcrypt-sha256": 1e3,
}

HASH_SEVERITY: Final[dict[str, str]] = {
    "md5": "critical",
    "md4": "critical",
    "md2": "critical",
    "ntlm": "critical",
    "lm": "critical",
    "sha1": "high",
    "des": "high",
    "3des": "high",
    "sha224": "medium",
    "sha256": "low",
    "sha512": "low",
    "pbkdf2": "low",
    "bcrypt": "info",
    "argon2": "info",
    "scrypt": "info",
    "yescrypt": "info",
}

SSH_WEAK_SETTINGS: Final[dict[str, tuple[str, str]]] = {
    "PermitRootLogin": ("Prohibits direct root SSH login, removing scripted brute force.", "high"),
    "PasswordAuthentication": ("Key-based auth removes the online password attack surface.", "high"),
    "PubkeyAuthentication": ("Key-based auth removes the online password attack surface.", "high"),
    "PermitEmptyPasswords": ("Accounts with blank passwords accept any login attempt.", "critical"),
    "MaxAuthTries": ("Caps attempts per connection so a run cannot guess more than 6 tries.", "medium"),
    "X11Forwarding": ("Tunnelling X11 exposes the desktop; unnecessary on servers.", "low"),
    "LoginGraceTime": ("A long grace period multiplies the number of parallel attempts allowed.", "low"),
    "AllowUsers": ("Restricts SSH login to a named allowlist of accounts.", "medium"),
    "ClientAliveInterval": ("Idle sessions are reaped instead of lingering as an unused foothold.", "info"),
}

DEFAULT_WORDLIST: Final = "wordlists/creds.txt"
CVE_DB_PATH: Final = "data/cve_db.json"
