"""Assessment modules.

Each module exposes a small set of functions that take plain options and return
a :class:`~redteam_toolkit.models.Report`. The CLI never does the analysis
itself, so every module is callable from a script or a test directly.

Two groups:

* **Active** (open a socket): :mod:`scanner`, :mod:`webscan`, :mod:`tls_audit`,
  :mod:`ssh_audit`, :mod:`attack`. All of them pass through
  :mod:`redteam_toolkit.guardrails` first.
* **Offline** (read a file, or reason locally): :mod:`password`,
  :mod:`hash_audit`, :mod:`logs`, :mod:`firewall_audit`, :mod:`phishing`,
  :mod:`cve_lookup`, :mod:`payload`. No network access, no authorization needed.
"""

from . import (
    attack,
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

#: Modules that open network connections and therefore require authorization.
NETWORK_MODULES = frozenset({"scanner", "webscan", "tls_audit", "ssh_audit", "attack"})

#: Modules that only read local files or reason locally.
OFFLINE_MODULES = frozenset(
    {"password", "hash_audit", "logs", "firewall_audit", "phishing", "cve_lookup", "payload"}
)

__all__ = [
    "NETWORK_MODULES",
    "OFFLINE_MODULES",
    "attack",
    "cve_lookup",
    "firewall_audit",
    "hash_audit",
    "logs",
    "password",
    "payload",
    "phishing",
    "scanner",
    "ssh_audit",
    "tls_audit",
    "webscan",
]
