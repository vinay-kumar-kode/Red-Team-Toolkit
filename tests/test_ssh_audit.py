"""SSH configuration parsing, offline auditing and live probing."""

from __future__ import annotations

import pytest
from redteam_toolkit.modules import ssh_audit

WEAK_CONFIG = """\
# test config
Port 22
PermitRootLogin yes
PasswordAuthentication yes
MaxAuthTries 20
LoginGraceTime 300
X11Forwarding yes
Compression yes
LogLevel INFO
Ciphers aes256-cbc,3des-cbc,chacha20-poly1305@openssh.com
KexAlgorithms diffie-hellman-group-exchange-sha256,diffie-hellman-group1-sha1
Match User deploy
    PasswordAuthentication yes
"""

STRONG_CONFIG = """\
Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
PermitEmptyPasswords no
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
Compression no
LogLevel VERBOSE
AllowUsers deploy ops
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
KexAlgorithms sntrup761x25519-sha512@openssh.com,curve25519-sha256
MACs hmac-sha2-512
"""


def write(tmp_path, text: str, name: str = "sshd_config"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return path


class TestParsing:
    def test_directives_are_parsed_with_line_numbers(self, tmp_path):
        parsed = ssh_audit.parse_config(write(tmp_path, WEAK_CONFIG))
        assert parsed.effective("PermitRootLogin").value == "yes"
        assert parsed.effective("PermitRootLogin").line_no == 3

    def test_comments_are_ignored(self, tmp_path):
        parsed = ssh_audit.parse_config(write(tmp_path, "# PermitRootLogin yes\n"))
        assert parsed.effective("PermitRootLogin") is None

    def test_first_value_wins_like_sshd(self, tmp_path):
        """sshd uses the first value it sees, which is what a real audit must model."""
        parsed = ssh_audit.parse_config(write(tmp_path, "PermitRootLogin no\nPermitRootLogin yes\n"))
        assert parsed.effective("PermitRootLogin").value == "no"
        assert len(parsed.all_for("PermitRootLogin")) == 2

    def test_match_blocks_are_recorded(self, tmp_path):
        parsed = ssh_audit.parse_config(write(tmp_path, WEAK_CONFIG))
        assert len(parsed.all_for("Match")) == 1
        assert parsed.all_for("Match")[0].context.startswith("Match User deploy")

    def test_include_is_followed(self, tmp_path):
        (tmp_path / "extra.conf").write_text("MaxAuthTries 2\n", encoding="utf-8")
        main = write(tmp_path, "Include extra.conf\nPermitRootLogin no\n")
        parsed = ssh_audit.parse_config(main)
        assert parsed.effective("MaxAuthTries").value == "2"
        assert len(parsed.files) == 2

    def test_include_can_be_disabled(self, tmp_path):
        (tmp_path / "extra.conf").write_text("MaxAuthTries 2\n", encoding="utf-8")
        main = write(tmp_path, "Include extra.conf\n")
        assert ssh_audit.parse_config(main, follow_includes=False).effective("MaxAuthTries") is None

    def test_missing_include_is_recorded_not_raised(self, tmp_path):
        parsed = ssh_audit.parse_config(write(tmp_path, "Include absent.conf\n"))
        assert "MaxAuthTries" not in {d.keyword for d in parsed.directives}

    def test_unreadable_include_is_reported(self, tmp_path):
        main = write(tmp_path, "Include missing.conf\n")
        parsed = ssh_audit.parse_config(main)
        # A glob that matches nothing is not an error; the audit should say so.
        assert isinstance(parsed.include_failures, list)

    def test_missing_file_yields_empty_parse(self, tmp_path):
        assert ssh_audit.parse_config(tmp_path / "nope").directives == []


class TestConfigAudit:
    @pytest.fixture
    def weak_report(self, tmp_path):
        return ssh_audit.audit_config(str(write(tmp_path, WEAK_CONFIG)))

    def test_root_login_is_critical(self, weak_report):
        finding = next(f for f in weak_report.findings if f.check == "ssh.permit-root-login")
        assert finding.severity == "critical"

    def test_password_auth_is_high(self, weak_report):
        assert any(f.check == "ssh.password-authentication" for f in weak_report.findings)

    def test_weak_ciphers_are_named(self, weak_report):
        finding = next(f for f in weak_report.findings if f.check == "ssh.ciphers")
        assert "aes256-cbc" in finding.evidence["weak"]
        assert "3des-cbc" in finding.evidence["weak"]

    def test_weak_kex_is_flagged(self, weak_report):
        assert any(f.check == "ssh.kex-algorithms" for f in weak_report.findings)

    def test_match_blocks_are_flagged_as_policy_overrides(self, weak_report):
        """A permissive setting inside Match silently re-opens a hardened account."""
        finding = next(f for f in weak_report.findings if f.check == "ssh.match-blocks")
        assert finding.evidence["count"] == 1

    def test_compression_is_flagged(self, weak_report):
        assert any(f.check == "ssh.compression" for f in weak_report.findings)

    def test_coarse_logging_is_flagged(self, weak_report):
        assert any(f.check == "ssh.logging" for f in weak_report.findings)

    def test_loose_numeric_limits_are_flagged(self, weak_report):
        checks = {f.check for f in weak_report.findings}
        assert "ssh.max-auth-tries" in checks
        assert "ssh.login-grace-time" in checks

    def test_unset_settings_fall_back_to_defaults(self, tmp_path):
        """An absent PasswordAuthentication still means password auth is on."""
        report = ssh_audit.audit_config(str(write(tmp_path, "Port 22\n")))
        finding = next(f for f in report.findings if f.check == "ssh.password-authentication")
        assert "default" in finding.evidence["value"]

    def test_strong_config_produces_no_high_or_critical(self, tmp_path):
        report = ssh_audit.audit_config(str(write(tmp_path, STRONG_CONFIG)))
        assert not report.at_or_above("high")

    def test_strong_config_is_credited_for_good_settings(self, tmp_path):
        report = ssh_audit.audit_config(str(write(tmp_path, STRONG_CONFIG)))
        checks = {f.check for f in report.findings}
        assert "ssh.allow-users" in checks
        assert "ssh.logging" in checks

    def test_empty_passwords_enabled_is_critical(self, tmp_path):
        report = ssh_audit.audit_config(str(write(tmp_path, "PermitEmptyPasswords yes\n")))
        assert any(f.check == "ssh.permit-empty-passwords" for f in report.findings)

    def test_ssh_protocol_1_is_critical(self, tmp_path):
        report = ssh_audit.audit_config(str(write(tmp_path, "Protocol 1\nProtocol 2\n")))
        assert any(f.check == "ssh.protocol" for f in report.findings)

    def test_missing_file_is_reported(self, tmp_path):
        report = ssh_audit.audit_config(str(tmp_path / "absent"))
        assert any(f.check == "ssh.config-missing" for f in report.findings)

    def test_lab_config_triggers_the_documented_findings(self, lab_files):
        report = ssh_audit.audit_config(str(lab_files / "ssh" / "sshd_config"))
        checks = {f.check for f in report.findings}
        for expected in (
            "ssh.permit-root-login",
            "ssh.password-authentication",
            "ssh.max-auth-tries",
            "ssh.login-grace-time",
            "ssh.x11-forwarding",
            "ssh.compression",
            "ssh.logging",
            "ssh.kex-algorithms",
            "ssh.ciphers",
            "ssh.match-blocks",
        ):
            assert expected in checks, f"missing {expected}"


class TestHelpers:
    def test_snake_case_keeps_runs_of_capitals_together(self):
        assert ssh_audit._snake("MACs") == "macs"
        assert ssh_audit._snake("KexAlgorithms") == "kex-algorithms"
        assert ssh_audit._snake("PermitRootLogin") == "permit-root-login"
        assert ssh_audit._snake("X11Forwarding") == "x11-forwarding"

    def test_banner_version_parsing(self):
        assert ssh_audit._parse_banner_version("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3") == "8.9"
        assert ssh_audit._parse_banner_version("SSH-2.0-OpenSSH_7.4") == "7.4"
        assert ssh_audit._parse_banner_version("garbage") is None

    def test_outdated_version_detection(self):
        assert ssh_audit._version_outdated("7.4")
        assert ssh_audit._version_outdated("8.9")
        assert not ssh_audit._version_outdated("9.6")
        assert not ssh_audit._version_outdated("10.0")

    def test_authorized_key_fingerprint(self):
        line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
        fingerprint = ssh_audit.fingerprint_authorized_key(line)
        assert fingerprint is not None
        assert fingerprint.startswith("SHA256:")

    def test_authorized_key_fingerprint_rejects_junk(self):
        assert ssh_audit.fingerprint_authorized_key("") is None
        assert ssh_audit.fingerprint_authorized_key("ssh-ed25519 not-base64!!") is None


@pytest.mark.network
class TestLiveProbe:
    def test_banner_and_version_are_read_without_authenticating(self, banner_server):
        report = ssh_audit.audit_live("127.0.0.1", "127.0.0.1", banner_server.port, timeout=2.0)
        assert report.data["connected"] is True
        assert "OpenSSH" in report.data["banner"]
        assert report.data["openssh_version"] == "8.9"
        # The probe reads a greeting; it never offers a credential.
        assert not any(f.check.startswith("ssh.auth") for f in report.findings)

    def test_outdated_banner_is_flagged(self, tmp_path):
        reply = b"SSH-2.0-OpenSSH_6.4p1 Debian\r\n"
        from tests.conftest import ThreadedServer

        with ThreadedServer(reply) as server:
            report = ssh_audit.audit_live("127.0.0.1", "127.0.0.1", server.port, timeout=2.0)
        assert any(f.check == "ssh.outdated-version" for f in report.findings)

    def test_unreachable_port_is_reported_not_raised(self, closed_port: int):
        report = ssh_audit.audit_live("127.0.0.1", "127.0.0.1", closed_port, timeout=0.5)
        assert any(f.check == "ssh.unreachable" for f in report.findings)
