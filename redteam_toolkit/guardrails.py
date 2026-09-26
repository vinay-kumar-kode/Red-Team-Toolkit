"""Authorization gate for anything that touches a network.

Two independent checks run before a module opens a socket:

1. **Acknowledgement.** The operator must confirm they are authorized. In a TTY
   that is an interactive prompt; non-interactively it is the ``--i-understand``
   flag, so scripted lab runs stay reproducible.
2. **Scope.** Resolved addresses must fall inside the permitted scope, which
   defaults to loopback plus RFC1918 space. Public internet addresses require
   ``--allow-public``. Cloud metadata and other non-yours ranges are refused
   outright and cannot be overridden.

The attack-side modules are simulation-only by design: they never authenticate
against a remote host. See ``docs/SAFETY.md``.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass

from .utils import console
from .utils.net import (
    BlockedTargetError,
    ResolutionError,
    classify,
    is_scope_allowed,
    resolve,
)

#: Scope permitted without any extra flag: loopback and private ranges.
DEFAULT_SCOPE: tuple[str, ...] = ("127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")

ACKNOWLEDGEMENT = (
    "This sends network traffic to a target you name.\n"
    "Only proceed if you own the target or have written permission to test it."
)


class AuthorizationError(PermissionError):
    """The operator did not satisfy the authorization gate."""


@dataclass(slots=True)
class TargetContext:
    """A validated target: the address that will actually be contacted."""

    requested: str
    address: str
    scope: str

    @property
    def label(self) -> str:
        return self.requested if self.address == self.requested else f"{self.requested} ({self.address})"


def authorize(
    target: str,
    allow_public: bool = False,
    scope: tuple[str, ...] = DEFAULT_SCOPE,
    i_understand: bool = False,
    assume_yes: bool = False,
    color: bool | None = None,
) -> TargetContext:
    """Validate and authorize ``target``, or raise.

    Raises :class:`AuthorizationError` when the operator has not acknowledged the
    terms or the target is outside scope, and :class:`BlockedTargetError` for
    ranges that are never permissible.
    """
    color = console.enable_color(color)

    try:
        addresses = resolve(target)
    except ResolutionError as exc:
        raise AuthorizationError(str(exc)) from exc

    for address in addresses:
        if classify(address) == "blocked":
            raise BlockedTargetError(
                f"refusing to probe {address}: this range is infrastructure that does not "
                "belong to the operator (metadata, CGNAT, multicast). It cannot be allowed."
            )

    if not i_understand and not _prompt_acknowledgement(assume_yes, color):
        raise AuthorizationError(
            "not authorized to proceed. Re-run with --i-understand to confirm you have "
            "written permission to test this target."
        )

    effective_scope = scope if not allow_public else ()
    ok, reason = is_scope_allowed(target, effective_scope)
    if not ok:
        raise AuthorizationError(
            f"{target} resolves to {addresses[0]} which is outside the default scope "
            f"({', '.join(scope)}). {reason}. Pass --allow-public if this is an authorized "
            "engagement, or --scope to widen the permitted ranges."
        )

    return TargetContext(requested=target, address=addresses[0], scope=reason)


def _prompt_acknowledgement(assume_yes: bool, color: bool) -> bool:
    if assume_yes or not sys.stdin.isatty():
        return False
    console.header("Authorization required", color=color)
    for line in ACKNOWLEDGEMENT.splitlines():
        console.info(line, color=color)
    try:
        answer = input("   Type 'yes' to continue: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("yes", "y")


def describe_target(target: str) -> list[str]:
    """Human-readable resolution notes for the report header."""
    lines = [f"requested: {target}"]
    try:
        addresses = resolve(target)
    except ResolutionError as exc:
        lines.append(f"resolution: failed ({exc})")
        return lines
    lines.append(f"addresses: {', '.join(addresses)}")
    lines.append(f"class: {classify(addresses[0])}")
    return lines
