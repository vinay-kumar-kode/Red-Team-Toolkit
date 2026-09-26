"""Authorization gate, address classification and scope enforcement."""

from __future__ import annotations

import pytest
from redteam_toolkit.guardrails import (
    DEFAULT_SCOPE,
    AuthorizationError,
    TargetContext,
    authorize,
    describe_target,
)
from redteam_toolkit.utils.net import (
    BlockedTargetError,
    ResolutionError,
    classify,
    is_scope_allowed,
    parse_ports,
    resolve,
)


class TestAddressClassification:
    @pytest.mark.parametrize(
        "address,expected",
        [
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("10.1.2.3", "private"),
            ("172.16.0.1", "private"),
            ("192.168.1.1", "private"),
            ("169.254.169.254", "blocked"),
            ("100.64.0.1", "blocked"),
            ("224.0.0.1", "blocked"),
            ("8.8.8.8", "public"),
        ],
    )
    def test_classification(self, address: str, expected: str):
        assert classify(address) == expected

    def test_garbage_is_unresolvable_not_crashing(self):
        assert classify("not-an-address") == "unresolvable"


class TestScope:
    def test_loopback_is_in_default_scope(self):
        ok, _reason = is_scope_allowed("127.0.0.1", DEFAULT_SCOPE)
        assert ok

    def test_rfc1918_is_in_default_scope(self):
        for address in ("10.0.0.5", "172.16.4.4", "192.168.1.1"):
            ok, _reason = is_scope_allowed(address, DEFAULT_SCOPE)
            assert ok, address

    def test_public_is_out_of_default_scope(self):
        ok, reason = is_scope_allowed("8.8.8.8", DEFAULT_SCOPE)
        assert not ok
        assert "outside" in reason

    def test_empty_allowlist_is_unrestricted(self):
        ok, reason = is_scope_allowed("8.8.8.8", ())
        assert ok
        assert reason == "unrestricted"

    def test_explicit_scope_is_honoured(self):
        ok, _reason = is_scope_allowed("8.8.8.8", ("8.8.8.8",))
        assert ok

    def test_cidr_scope_is_honoured(self):
        ok, _reason = is_scope_allowed("10.5.5.5", ("10.0.0.0/8",))
        assert ok

    def test_every_resolved_address_must_be_in_scope(self):
        """A hostname resolving to one allowed and one disallowed address must fail."""
        ok, _reason = is_scope_allowed("localhost", ("10.0.0.0/8",))
        assert not ok

    def test_unresolvable_target_fails_the_scope_check(self):
        ok, reason = is_scope_allowed("this-host-does-not-exist.invalid", DEFAULT_SCOPE)
        assert not ok
        assert "resolve" in reason.lower() or "cannot" in reason.lower()


class TestAuthorization:
    def test_acknowledgement_is_required(self):
        """Without the flag, or an interactive yes, the gate is closed."""
        with pytest.raises(AuthorizationError, match="not authorized"):
            authorize("127.0.0.1", i_understand=False, assume_yes=True)

    def test_acknowledgement_admits_loopback(self):
        ctx = authorize("127.0.0.1", i_understand=True, assume_yes=True)
        assert isinstance(ctx, TargetContext)
        assert ctx.address == "127.0.0.1"
        assert ctx.requested == "127.0.0.1"

    def test_public_needs_allow_public(self):
        with pytest.raises(AuthorizationError, match="outside the default scope"):
            authorize("8.8.8.8", i_understand=True, assume_yes=True)

    def test_allow_public_admits_a_public_address(self):
        ctx = authorize("8.8.8.8", allow_public=True, i_understand=True, assume_yes=True)
        assert ctx.address == "8.8.8.8"
        assert ctx.scope == "unrestricted"

    def test_extra_scope_is_honoured(self):
        ctx = authorize("8.8.8.8", scope=("8.8.8.8",), i_understand=True, assume_yes=True)
        assert ctx.address == "8.8.8.8"

    @pytest.mark.parametrize(
        "address",
        ["169.254.169.254", "100.64.0.1", "224.0.0.1", "240.0.0.1"],
    )
    def test_blocked_ranges_cannot_be_allowlisted(self, address: str):
        """Metadata and other non-yours infrastructure stays refused regardless."""
        with pytest.raises(BlockedTargetError):
            authorize(
                address,
                allow_public=True,
                scope=("0.0.0.0/0",),
                i_understand=True,
                assume_yes=True,
            )

    def test_unresolvable_target_is_an_authorization_error(self):
        with pytest.raises(AuthorizationError):
            authorize("this-host-does-not-exist.invalid", i_understand=True, assume_yes=True)

    def test_localhost_resolves_and_is_labelled(self):
        ctx = authorize("localhost", i_understand=True, assume_yes=True)
        assert ctx.requested == "localhost"
        assert ctx.address in ("127.0.0.1", "::1")
        assert ctx.label.startswith("localhost (")

    def test_bracketed_ipv6_is_accepted(self):
        ctx = authorize("[::1]", i_understand=True, assume_yes=True)
        assert ctx.address == "::1"


class TestDescribeTarget:
    def test_describes_resolution_and_class(self):
        lines = describe_target("127.0.0.1")
        text = " ".join(lines)
        assert "requested: 127.0.0.1" in text
        assert "addresses: 127.0.0.1" in text
        assert "class: loopback" in text

    def test_unresolvable_target_is_described_not_raised(self):
        text = " ".join(describe_target("nope.invalid"))
        assert "resolution: failed" in text


class TestResolve:
    def test_loopback(self):
        assert "127.0.0.1" in resolve("127.0.0.1")

    def test_brackets_are_stripped(self):
        assert resolve("[127.0.0.1]") == ["127.0.0.1"]

    def test_empty_input_raises(self):
        with pytest.raises(ResolutionError):
            resolve("")

    def test_bad_hostname_raises(self):
        with pytest.raises(ResolutionError):
            resolve("this-host-does-not-exist.invalid")


class TestPortParsingRejectsAbuse:
    @pytest.mark.parametrize("spec", ["1-5000", "1-9000", "1-65000"])
    def test_wide_range_is_refused(self, spec: str):
        with pytest.raises(ValueError, match="too wide"):
            parse_ports(spec)

    def test_many_discrete_ports_are_refused(self):
        """A long comma list bypasses the per-range width guard, so the total
        count needs its own limit."""
        spec = ",".join(str(10000 + i) for i in range(5000))
        with pytest.raises(ValueError, match="more than 4096"):
            parse_ports(spec)
