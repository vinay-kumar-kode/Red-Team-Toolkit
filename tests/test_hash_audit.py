"""Password hash dump auditing."""

from __future__ import annotations

import pytest
from redteam_toolkit.modules import hash_audit

Bcrypt12 = "$2y$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewYyk5WFB5YJ0mSj"
Bcrypt04 = "$2y$04$Lp2XyMGS1g0KQ0YVQ1pQeO7dJ3Kx1F0VvB6T1R8kMzXkJ2L0vXy9Wa"
Argon2id = "$argon2id$v=19$m=4096,t=1,p=1$c29tZXNhbHQ$Yn5Zp8Xq7bGxK1l0kJ2mN4pQ6rS8tU0vW2xY4zA6bC"
Scrypt = "$scrypt$ln=16,r=8,p=1$abcdefghijklmnopqrstuv$UVkZ3N5bFVxY2xkQ2hpR3JvYw=="
Md5crypt = "$1$salt1234$DIQ7XkNvJ3lm0YqPw0HDw1"


class TestIdentify:
    @pytest.mark.parametrize(
        "digest,expected",
        [
            ("5f4dcc3b5aa765d61d8327deb882cf99", "md5"),
            ("da39a3ee5e6b4b0d3255bfef95601890afd80709", "sha1"),
            ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "sha256"),
            (Bcrypt12, "bcrypt"),
            (Bcrypt04, "bcrypt"),
            (Argon2id, "argon2id"),
            (Scrypt, "scrypt"),
            (Md5crypt, "md5crypt"),
        ],
    )
    def test_algorithm_detection(self, digest: str, expected: str):
        assert hash_audit.identify(digest)[0] == expected

    def test_bcrypt_cost_is_extracted(self):
        assert hash_audit.identify(Bcrypt12)[1] == "12"
        assert hash_audit.identify(Bcrypt04)[1] == "04"

    def test_argon2_parameters_are_extracted(self):
        assert hash_audit.identify(Argon2id)[1] == "4096,1,1"

    def test_unknown_input_is_reported_as_unknown(self):
        assert hash_audit.identify("not-a-hash-at-all")[0] == "unknown"

    def test_base64_padding_is_tolerated(self):
        """A truncated base64 field must still be recognised, not fall through."""
        assert hash_audit.identify(Scrypt)[0] == "scrypt"


class TestParsing:
    def test_username_colon_hash_is_split(self):
        entry = hash_audit._entry_from_line(1, f"admin:{Bcrypt12}")
        assert entry is not None
        assert entry.identifier == "admin"
        assert entry.algorithm == "bcrypt"

    def test_bare_hash_is_accepted(self):
        entry = hash_audit._entry_from_line(1, Bcrypt12)
        assert entry is not None
        assert entry.identifier == "-"

    def test_comments_and_blanks_are_skipped(self, tmp_path):
        path = tmp_path / "dump.txt"
        path.write_text(f"# a comment\n\nadmin:{Bcrypt12}\n\n   \n", encoding="utf-8")
        entries = hash_audit.parse_dump(path)
        assert len(entries) == 1

    def test_unsalted_hashes_are_noted(self):
        entry = hash_audit._entry_from_line(1, "5f4dcc3b5aa765d61d8327deb882cf99")
        assert entry is not None
        assert "unsalted" in entry.note

    def test_crack_time_is_faster_for_weak_hashes(self):
        weak = hash_audit._entry_from_line(1, "5f4dcc3b5aa765d61d8327deb882cf99")
        strong = hash_audit._entry_from_line(1, Bcrypt12)
        assert weak is not None and strong is not None
        assert weak.crack_seconds < strong.crack_seconds

    def test_missing_file_is_reported(self, tmp_path):
        report = hash_audit.audit(path=str(tmp_path / "nope.txt"))
        assert any(f.check == "hash.dump-missing" for f in report.findings)

    def test_empty_input_is_reported(self):
        report = hash_audit.audit(hashes=[])
        assert any(f.check == "hash.empty" for f in report.findings)


class TestReport:
    @pytest.fixture
    def dump(self, tmp_path):
        path = tmp_path / "dump.txt"
        path.write_text(
            "admin:5f4dcc3b5aa765d61d8327deb882cf99\n"
            f"admin:{Bcrypt12}\n"
            f"reports:{Bcrypt04}\n"
            f"dba:{Argon2id}\n"
            "svc_legacy:5f4dcc3b5aa765d61d8327deb882cf99\n"
            f"webadmin:{Scrypt}\n"
            f"olduser:{Md5crypt}\n"
            "notahash:thisisnotahashatalljustatext\n",
            encoding="utf-8",
        )
        return str(path)

    def test_weak_algorithm_is_critical(self, dump: str):
        report = hash_audit.audit(path=dump)
        finding = next(f for f in report.findings if f.check == "hash.algorithm-md5")
        assert finding.severity == "critical"

    def test_low_cost_parameters_are_reported(self, dump: str):
        report = hash_audit.audit(path=dump)
        weak = [f for f in report.findings if f.check == "hash.low-cost-params"]
        assert weak
        # The cost-4 bcrypt and the 4 MiB argon2id must both be named.
        named = {name for f in weak for name in f.evidence["weak"]}
        assert any("bcrypt" in entry for entry in named) or any("04" in entry for entry in named)
        assert any(f.severity == "high" for f in weak)

    def test_reused_password_is_detected(self, dump: str):
        """Identical unsalted digests mean identical passwords across accounts."""
        report = hash_audit.audit(path=dump)
        reuse = next(f for f in report.findings if f.check == "hash.reused-passwords")
        assert reuse.severity == "high"

    def test_non_hash_value_is_flagged(self, dump: str):
        report = hash_audit.audit(path=dump)
        assert any(f.check == "hash.unknown-format" for f in report.findings)

    def test_aggregate_risk_with_a_breach_size(self, dump: str):
        report = hash_audit.audit(path=dump, total_passwords=1_000_000)
        assert any(f.check == "hash.aggregate-risk" for f in report.findings)

    def test_no_entry_contains_the_raw_digest(self, dump: str):
        """A finding is written to disk; it must not become a credential dump."""
        report = hash_audit.audit(path=dump)
        assert "5f4dcc3b5aa765d61d8327deb882cf99" not in report.to_json()

    def test_report_serialises(self, dump: str):
        import json

        json.loads(hash_audit.audit(path=dump).to_json())

    def test_single_hash_mode(self):
        report = hash_audit.audit(single=f"admin:{Bcrypt12}")
        assert report.data["entries"] == 1
        assert report.data["results"][0]["algorithm"] == "bcrypt"

    def test_stdin_list_mode(self):
        report = hash_audit.audit(hashes=[f"a:{Bcrypt12}", "b:5f4dcc3b5aa765d61d8327deb882cf99"])
        assert report.data["entries"] == 2

    def test_lab_dump_exercises_every_detector(self, lab_files):
        report = hash_audit.audit(path=str(lab_files / "hashes" / "dump.txt"))
        checks = {f.check for f in report.findings}
        assert "hash.algorithm-md5" in checks
        assert "hash.reused-passwords" in checks
        assert "hash.unknown-format" in checks
