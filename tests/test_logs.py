"""Authentication log parsing and attack-pattern detection."""

from __future__ import annotations

import pytest
from redteam_toolkit.modules import logs


def write(tmp_path, text: str, name: str = "auth.log"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


class TestEventClassification:
    @pytest.mark.parametrize(
        "line,outcome,user,ip",
        [
            (
                "Mar  4 10:00:00 host sshd[1]: Accepted password for alice from 10.0.0.5 port 22 ssh2",
                "success",
                "alice",
                "10.0.0.5",
            ),
            (
                "Mar  4 10:00:00 host sshd[1]: Failed password for root from 203.0.113.9 port 22 ssh2",
                "failed",
                "root",
                "203.0.113.9",
            ),
            (
                "Mar  4 10:00:00 host sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2",
                "failed",
                "admin",
                "203.0.113.9",
            ),
            (
                "Mar  4 10:00:00 host sshd[1]: Accepted publickey for deploy from 10.0.0.9 port 22 ssh2",
                "success",
                "deploy",
                "10.0.0.9",
            ),
            (
                'Mar  4 10:00:00 web nginx: 401#0: *1 open() failed, client: 198.51.100.5, user="jsmith"',
                "failed",
                "jsmith",
                "198.51.100.5",
            ),
            (
                "Mar  4 10:00:00 host sshd[1]: pam_unix(sshd:auth): authentication failure; rhost=203.0.113.7 user=root",
                "failed",
                "root",
                "203.0.113.7",
            ),
        ],
    )
    def test_common_formats_are_parsed(self, line: str, outcome: str, user: str, ip: str):
        parsed = logs._classify(line)
        assert parsed[0] == outcome
        assert parsed[1] == user
        assert parsed[2] == ip

    def test_unrelated_lines_are_classified_as_other(self):
        assert logs._classify("Mar  4 10:00:00 host kernel: [1.0] eth0: Link is Up")[0] is None

    def test_ambiguous_line_prefers_the_failure(self):
        line = "Mar  4 10:00:00 host sshd[1]: login failed for bob from 10.0.0.1"
        outcome, user, _ip = logs._classify(line)
        assert outcome == "failed"
        assert user == "bob"


class TestTimestampParsing:
    def test_syslog_timestamp_gets_a_year_inferred_from_the_file_mtime(self, tmp_path):
        """syslog omits the year; without inference every log spans a year."""
        import datetime
        import os

        path = tmp_path / "auth.log"
        path.write_text("Mar  4 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")
        stamp = datetime.datetime(2026, 3, 4, 12, 0, 0).timestamp()
        os.utime(path, (stamp, stamp))

        events = list(logs._parse(path))
        assert events[0].when is not None
        assert events[0].when.year == 2026

    def test_a_rolled_over_log_does_not_land_in_the_future(self, tmp_path):
        import datetime
        import os

        path = tmp_path / "old.log"
        path.write_text("Dec 28 23:59:00 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\n")
        stamp = datetime.datetime(2026, 1, 2, 0, 30, 0).timestamp()
        os.utime(path, (stamp, stamp))

        events = list(logs._parse(path))
        assert events[0].when is not None
        assert events[0].when <= datetime.datetime(2026, 1, 2, 0, 30, tzinfo=datetime.timezone.utc)

    @pytest.mark.parametrize(
        "line",
        [
            "2026-03-04T10:00:00Z host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "2026-03-04 10:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "Mon, 4 Mar 2026 10:00:00 +0000 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ],
    )
    def test_explicit_timestamp_formats(self, line: str):
        outcome, _user, _ip = logs._classify(line)
        assert outcome == "failed"


class TestAttackDetection:
    def test_brute_force_against_one_account(self, tmp_path):
        lines = [
            f"Mar  4 10:00:{i:02d} host sshd[1]: Failed password for root from 203.0.113.44 port {40000 + i} ssh2"
            for i in range(30)
        ]
        report = logs.analyze(write(tmp_path, "\n".join(lines)))
        assert any(f.check == "log.bruteforce-source" for f in report.findings)
        top = report.data["top_sources"][0]
        assert top == "203.0.113.44"

    def test_fail_then_success_is_flagged_critical(self, tmp_path):
        """The highest-signal event in any auth log."""
        lines = [
            f"Mar  4 10:00:{i:02d} host sshd[1]: Failed password for root from 203.0.113.44 port {40000 + i} ssh2"
            for i in range(20)
        ]
        lines.append(
            "Mar  4 10:00:25 host sshd[1]: Accepted password for root from 203.0.113.44 port 40099 ssh2"
        )
        report = logs.analyze(write(tmp_path, "\n".join(lines)))
        indicator = next(f for f in report.findings if f.check == "log.compromise-indicator")
        assert indicator.severity == "critical"
        assert "203.0.113.44" in indicator.detail

    def test_success_after_failure_is_not_reported_when_there_were_few_failures(self, tmp_path):
        lines = [
            "Mar  4 10:00:00 host sshd[1]: Failed password for alice from 10.0.0.5 port 1 ssh2",
            "Mar  4 10:00:10 host sshd[1]: Accepted password for alice from 10.0.0.5 port 2 ssh2",
        ]
        report = logs.analyze(write(tmp_path, "\n".join(lines)))
        assert not any(f.check == "log.compromise-indicator" for f in report.findings)

    def test_password_spray_is_distinguished_from_brute_force(self, tmp_path):
        """Spraying stays under the per-account lockout threshold by design."""
        accounts = [f"user{index}" for index in range(12)]
        lines = []
        for round_index in range(2):
            for index, account in enumerate(accounts):
                second = round_index * 12 + index
                lines.append(
                    f"Mar  4 11:00:{second:02d} web nginx: 401#0: open() failed, "
                    f'client: 198.51.100.9, user="{account}"'
                )
        report = logs.analyze(write(tmp_path, "\n".join(lines)), threshold=5, spray_threshold=5)
        assert any(f.check == "log.password-spray" for f in report.findings)

    def test_single_account_flood_is_not_called_a_spray(self, tmp_path):
        lines = [
            f"Mar  4 11:00:{i:02d} host sshd[1]: Failed password for root from 198.51.100.9 port {40000 + i} ssh2"
            for i in range(20)
        ]
        report = logs.analyze(write(tmp_path, "\n".join(lines)))
        assert not any(f.check == "log.password-spray" for f in report.findings)

    def test_generic_account_probing_is_reported(self, tmp_path):
        lines = [
            f"Mar  4 12:00:{i:02d} host sshd[1]: Failed password for invalid user {name} from 203.0.113.5 port {40000 + i} ssh2"
            for i, name in enumerate(["root", "admin", "oracle", "postgres", "test", "guest"])
        ]
        report = logs.analyze(write(tmp_path, "\n".join(lines)))
        enumeration = next(f for f in report.findings if f.check == "log.account-enumeration")
        assert "admin" in enumeration.evidence["users"]

    def test_failure_burst_is_detected(self, tmp_path):
        # A quiet baseline of about one failure per minute, then 20 failures
        # inside a single 60-second window.
        lines = [
            f"Mar  4 10:{i:02d}:00 host sshd[1]: Failed password for x{i} from 10.0.0.{i % 5 + 2} port 1 ssh2"
            for i in range(20)
        ]
        lines.extend(
            f"Mar  4 12:00:{i:02d} host sshd[1]: Failed password for root from 203.0.113.44 port {40000 + i} ssh2"
            for i in range(20)
        )
        report = logs.analyze(write(tmp_path, "\n".join(lines)))
        assert any(f.check == "log.failure-burst" for f in report.findings)


class TestCleanLog:
    def test_normal_traffic_produces_no_attack_findings(self, tmp_path):
        lines = [
            f"Mar  4 09:00:{i:02d} host sshd[1]: Accepted password for user{i % 5} from 10.0.0.{i % 20 + 2} port 22 ssh2"
            for i in range(60)
        ]
        report = logs.analyze(write(tmp_path, "\n".join(lines)))
        attack_checks = {
            "log.bruteforce-source",
            "log.password-spray",
            "log.compromise-indicator",
            "log.account-enumeration",
            "log.distributed-attack",
            "log.failure-burst",
        }
        assert not ({f.check for f in report.findings} & attack_checks)

    def test_log_with_no_auth_events_says_so(self, tmp_path):
        report = logs.analyze(write(tmp_path, "line one\nline two\nline three\n"))
        assert any(f.check == "log.no-auth-events" for f in report.findings)

    def test_missing_file_is_reported_not_raised(self, tmp_path):
        report = logs.analyze(str(tmp_path / "absent.log"))
        assert any(f.check == "log.missing" for f in report.findings)


class TestAggregation:
    def test_source_profiles_carry_rate_and_span(self, tmp_path):
        lines = [
            f"Mar  4 14:00:{i:02d} host sshd[1]: Failed password for root from 203.0.113.44 port {40000 + i} ssh2"
            for i in range(20)
        ]
        report = logs.analyze(write(tmp_path, "\n".join(lines)))
        source = report.data["sources"][0]
        assert source["failures"] == 20
        assert source["span_seconds"] if "span_seconds" in source else source["failures"] == 20
        assert source["rate_per_minute"] > 0
        assert source["distinct_users"] == 1

    def test_timeline_buckets_are_produced(self, tmp_path):
        lines = [
            f"Mar  4 15:00:{i:02d} host sshd[1]: Failed password for root from 203.0.113.44 port {40000 + i} ssh2"
            for i in range(20)
        ]
        report = logs.analyze(write(tmp_path, "\n".join(lines)), window_seconds=60)
        assert report.data["timeline_buckets"]
        assert sum(b["failures"] for b in report.data["timeline_buckets"]) == 20

    def test_thresholds_are_respected(self, tmp_path):
        lines = [
            f"Mar  4 16:00:{i:02d} host sshd[1]: Failed password for root from 203.0.113.44 port {40000 + i} ssh2"
            for i in range(3)
        ]
        path = write(tmp_path, "\n".join(lines))
        assert not any(f.check == "log.bruteforce-source" for f in logs.analyze(path, threshold=10).findings)
        assert any(f.check == "log.bruteforce-source" for f in logs.analyze(path, threshold=2).findings)

    def test_report_serialises(self, tmp_path):
        lines = ["Mar  4 17:00:00 host sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"]
        import json

        json.loads(logs.analyze(write(tmp_path, "\n".join(lines))).to_json())

    def test_lab_log_produces_the_documented_findings(self, lab_files):
        report = logs.analyze(str(lab_files / "logs" / "auth.log"))
        checks = {f.check for f in report.findings}
        assert "log.bruteforce-source" in checks
        assert "log.password-spray" in checks
        assert "log.compromise-indicator" in checks
        assert "log.account-enumeration" in checks
