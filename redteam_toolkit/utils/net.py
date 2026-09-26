"""Networking helpers: safe resolution, address classification, port parsing."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from pathlib import Path

#: Address ranges never worth probing even on a lab, because a mistake here
#: reaches infrastructure that is not yours (link-local metadata services, etc).
BLOCKED_NETWORKS: tuple[str, ...] = (
    "169.254.0.0/16",  # link-local, includes cloud metadata at 169.254.169.254
    "100.64.0.0/10",  # carrier-grade NAT
    "192.0.0.0/24",  # IETF protocol assignments
    "198.18.0.0/15",  # benchmarking
    "224.0.0.0/4",  # multicast
    "240.0.0.0/4",  # reserved
)

LOCAL_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"})


class ResolutionError(ValueError):
    """Hostname could not be resolved to any address."""


class BlockedTargetError(PermissionError):
    """Target resolves into a range this toolkit refuses to probe."""


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_ports(spec: str | Iterable[int] | None, default: Iterable[int] = ()) -> list[int]:
    """Parse ``"22,80,8000-8010"`` into a sorted, de-duplicated port list."""
    if spec is None or spec == "":
        return sorted(set(default))
    if not isinstance(spec, str):
        return sorted({int(p) for p in spec})

    ports: set[int] = set()
    for chunk in spec.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            start_text, _, end_text = chunk.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ValueError(f"invalid port range: {chunk!r}") from exc
            if start > end:
                raise ValueError(f"reversed port range: {chunk!r}")
            if not start > 0 or end > 65535:
                raise ValueError(f"port out of range 1-65535: {chunk!r}")
            if end - start > 4096:
                raise ValueError(f"port range too wide (max 4096): {chunk!r}")
            ports.update(range(start, end + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise ValueError(f"invalid port: {chunk!r}") from exc
            if not 0 < port <= 65535:
                raise ValueError(f"port out of range 1-65535: {chunk!r}")
            ports.add(port)

    if len(ports) > 4096:
        raise ValueError("refusing to probe more than 4096 ports at once")
    return sorted(ports)


def resolve(target: str) -> list[str]:
    """Resolve ``target`` to every address, IPv4 first. Raises :class:`ResolutionError`."""
    target = target.strip().strip("[]")
    if not target:
        raise ResolutionError("empty target")

    if is_ip(target):
        return [target]

    try:
        infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ResolutionError(f"cannot resolve {target!r}: {exc.strerror or exc}") from exc

    seen: list[str] = []
    for info in infos:
        # getaddrinfo returns a sockaddr union; for INET/INET6 the first element
        # is the address string, but the declared type is broader than that.
        address = str(info[4][0])
        if address not in seen:
            seen.append(address)
    if not seen:
        raise ResolutionError(f"no addresses for {target!r}")
    return seen


def first_address(target: str) -> str:
    return resolve(target)[0]


def classify(address: str) -> str:
    """Human label for an address: loopback/private/link-local/public."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "unresolvable"

    if ip.is_loopback:
        return "loopback"
    if any(ip in ipaddress.ip_network(net) for net in BLOCKED_NETWORKS):
        return "blocked"
    if ip.is_link_local:
        return "link-local"
    if ip.is_private:
        return "private"
    if ip.is_reserved or ip.is_multicast:
        return "reserved"
    return "public"


def is_scope_allowed(target: str, allow: Iterable[str]) -> tuple[bool, str]:
    """Check every resolved address of ``target`` against an allowlist of CIDRs/addresses.

    Returns ``(ok, reason)``. An empty allowlist means "no restriction", which is
    only reachable when the caller already satisfied the acknowledgement gate.
    """
    allowlist = [a for a in allow if a]
    if not allowlist:
        return True, "unrestricted"

    try:
        addresses = resolve(target)
    except ResolutionError as exc:
        return False, str(exc)

    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False, f"unparseable address {address!r}"
        for entry in allowlist:
            try:
                if ip in ipaddress.ip_network(entry, strict=False):
                    break
            except ValueError:
                if address == entry:
                    break
        else:
            return False, f"{address} is outside the permitted scope {sorted(set(allowlist))}"
    return True, "in scope"


def guess_url_scheme(port: int) -> str:
    return "https" if port in (443, 8443, 4443, 9443) else "http"


def expand_wordlist(path: str) -> list[str]:
    """Read a wordlist, dropping blanks and ``#`` comments, preserving order."""
    with Path(path).open(encoding="utf-8", errors="replace") as handle:
        return [line.strip() for line in handle if line.strip() and not line.startswith("#")]
