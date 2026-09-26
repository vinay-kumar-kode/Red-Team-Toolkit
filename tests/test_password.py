"""Password strength scoring, pattern detection and wordlist estimation."""

from __future__ import annotations

import pytest
from redteam_toolkit.modules import password as pw


class TestCharset:
    def test_charset_size_grows_with_classes(self):
        lower = pw.charset_size("abcdef")
        mixed = pw.charset_size("Abcdef")
        full = pw.charset_size("Abcdef123!")
        assert lower < mixed < full

    def test_charset_size_never_zero(self):
        assert pw.charset_size("") == 1

    def test_mask_reports_present_classes(self):
        assert pw.charset_mask("abc") == "l"
        assert pw.charset_mask("Abc123!") == "luds"
        assert pw.charset_mask("") == "-"

    def test_raw_entropy_scales_with_length(self):
        assert pw.raw_entropy("Xk9$mQ2#vLp8wR7") > pw.raw_entropy("Xk9$mQ")


class TestPatternDetection:
    @pytest.mark.parametrize(
        "password,pattern",
        [
            ("password", "common-password"),
            ("P@ssw0rd", "common-password"),
            ("aaaaaaaaaaaa", "repeat"),
            ("qwertyui", "keyboard"),
            ("abcdefgh", "sequence"),
            ("Summer2024", "date"),
        ],
    )
    def test_expected_pattern_is_found(self, password: str, pattern: str):
        matches = pw.find_matches(password, pw.load_dictionary())
        assert pattern in {m.pattern for m in matches}, [m.pattern for m in matches]

    def test_repeat_run_is_one_match_not_many(self):
        """A long run is a single cheap pattern; splitting it inflates the score."""
        matches = pw.find_matches("a" * 12, pw.load_dictionary())
        assert len(matches) == 1
        assert matches[0].pattern == "repeat"
        assert matches[0].length == 12

    def test_leet_substitution_is_still_a_dictionary_hit(self):
        matches = pw.find_matches("p4ssw0rd", pw.load_dictionary())
        assert any(m.pattern in ("common-password", "dictionary") for m in matches)

    def test_strong_random_password_has_no_patterns(self):
        matches = pw.find_matches("Xk9$mQ2#vLp8wR7", pw.load_dictionary())
        assert matches == []

    def test_user_input_is_flagged_when_embedded(self):
        a = pw.assess("summer-of-jsmith-2024", user_inputs=["jsmith"])
        assert any(m.pattern == "user-input" for m in a.matches)


class TestScoring:
    @pytest.mark.parametrize(
        "password,expected_max",
        [
            ("password", 0),
            ("admin123", 0),
            ("P@ssw0rd", 0),
            ("qwerty123456", 0),
            ("aaaaaaaaaaaa", 0),
            ("summer2019", 0),
            ("12345678901234567890", 1),
        ],
    )
    def test_weak_passwords_score_very_low(self, password: str, expected_max: int):
        assert pw.assess(password).score <= expected_max

    @pytest.mark.parametrize("password", ["Xk9$mQ2#vLp8wR7", "Tr0ub4dor&3", "correct horse battery staple"])
    def test_strong_passwords_score_high(self, password: str):
        assert pw.assess(password).score >= 3

    def test_decoration_does_not_rescue_a_dictionary_word(self):
        """The whole point of pattern-based scoring."""
        plain = pw.assess("password")
        decorated = pw.assess("P@ssw0rd!!!2024")
        assert decorated.score <= plain.score
        assert decorated.entropy_bits <= pw.raw_entropy("P@ssw0rd!!!2024")

    def test_length_beats_character_classes(self):
        short_complex = pw.assess("Xk9$mQ")
        # Deliberately not a keyboard walk, so length is the only variable.
        long_simple = pw.assess("mjq4xzvb7wprk9tdhy")
        assert long_simple.score >= short_complex.score

    def test_empty_password_is_handled(self):
        a = pw.assess("")
        assert a.score == 0
        assert a.label == "empty"
        assert a.warnings

    def test_effective_entropy_never_exceeds_raw(self):
        for password in ("password", "aaaaaaaaaaaa", "Xk9$mQ2#vLp8wR7", "12345678901234567890"):
            a = pw.assess(password)
            assert a.entropy_bits <= a.raw_entropy_bits + 0.05

    def test_crack_time_ordering_online_slower_than_offline(self):
        a = pw.assess("Summer2019")
        assert a.offline_time < a.online_time

    def test_suggestions_are_always_offered(self):
        assert pw.assess("Xk9$mQ2#vLp8wR7").suggestions


class TestDurationFormatting:
    @pytest.mark.parametrize(
        "seconds,fragment",
        [
            (0.4, "instantly"),
            (30, "second"),
            (120, "minute"),
            (7200, "hour"),
            (172800, "day"),
            (5184000, "month"),
            (31536000, "year"),
        ],
    )
    def test_units(self, seconds: float, fragment: str):
        assert fragment in pw.format_duration(seconds)


class TestReports:
    def test_single_password_report_has_a_finding_for_weak(self):
        report = pw.check("password")
        assert report.findings
        assert report.severity in ("critical", "high")
        assert report.data["score"] == 0

    def test_single_password_report_is_clean_for_strong(self):
        report = pw.check("Xk9$mQ2#vLp8wR7")
        assert not report.at_or_above("medium")

    def test_password_is_not_stored_in_report_data(self):
        """A report file must not become a credential leak."""
        report = pw.check("hunter2")
        serialised = report.to_json()
        assert "hunter2" not in serialised

    def test_batch_report_counts_and_ranks(self):
        report = pw.check_many(["password", "admin123", "Xk9$mQ2#vLp8wR7"])
        assert report.data["checked"] == 3
        assert report.data["weakest"] in ("#1", "#2")
        assert report.data["by_score"]["very weak"] == 2
        assert report.at_or_above("high")

    def test_batch_never_stores_the_passwords(self):
        report = pw.check_many(["secretone", "secrettwo"])
        assert "secretone" not in report.to_json()

    def test_batch_honours_user_inputs(self):
        """--user must not be silently ignored when reading a list."""
        report = pw.check_many(["jsmith-Summer2024", "Xk9$mQ2#vLp8wR7"], user_inputs=["jsmith"])
        assert any(f.check == "pwd.batch-user-input" for f in report.findings)

    def test_batch_records_which_patterns_fired(self):
        report = pw.check_many(["jsmith-Summer2024"], user_inputs=["jsmith"])
        patterns = report.data["results"][0]["patterns"]
        assert "user-input" in patterns
        assert "common-password" in patterns
        assert "date" in patterns

    def test_batch_user_input_only_fires_when_present(self):
        """A username that does not appear in the candidate is not a finding."""
        report = pw.check_many(["Summer2024"], user_inputs=["jsmith"])
        assert "user-input" not in report.data["results"][0]["patterns"]
        assert not any(f.check == "pwd.batch-user-input" for f in report.findings)

    def test_batch_of_all_strong_passwords_is_quiet(self):
        report = pw.check_many(["Xk9$mQ2#vLp8wR7", "Tr0ub4dor&3", "qG7#mZ2$vB9!wT4x"])
        assert not report.at_or_above("high")


class TestComboEstimate:
    @pytest.fixture
    def wordlist(self, tmp_path):
        path = tmp_path / "combos.txt"
        path.write_text(
            "# comment line\nadmin:admin\nadmin:admin123\nroot:toor\nnotwellformed\njsmith:password\n",
            encoding="utf-8",
        )
        return str(path)

    def test_reports_size_and_offline_nature(self, wordlist: str):
        report = pw.combo_estimate(wordlist)
        assert report.data["lines"] == 5
        assert report.data["wellformed_combos"] == 4
        assert report.data["malformed_lines"] == 1

    def test_flags_weak_passwords_in_the_list(self, wordlist: str):
        report = pw.combo_estimate(wordlist)
        assert report.data["weak_password_count"] > 0
        usernames = {w["username"] for w in report.data["weak_passwords"]}
        assert "admin" in usernames

    def test_estimates_time_to_exhaust(self, wordlist: str):
        report = pw.combo_estimate(wordlist)
        assert report.data["seconds_unthrottled"] > 0
        assert "exhaustion_time_unthrottled" in report.data
        # The credential stage is offline only: no target is ever contacted.
        assert report.data["wordlist"] == wordlist

    def test_missing_file_is_reported_not_raised(self, tmp_path):
        report = pw.combo_estimate(str(tmp_path / "nope.txt"))
        assert any(f.check == "pwd.wordlist-missing" for f in report.findings)


class TestDictionaryLoading:
    def test_builtin_common_passwords_are_present(self):
        dictionary = pw.load_dictionary()
        assert "password" in dictionary
        assert "admin123" in dictionary

    def test_extra_wordlist_is_merged(self, tmp_path):
        path = tmp_path / "extra.txt"
        path.write_text("zolandphrase\n", encoding="utf-8")
        dictionary = pw.load_dictionary([str(path)])
        assert "zolandphrase" in dictionary

    def test_missing_extra_wordlist_is_ignored(self, tmp_path):
        dictionary = pw.load_dictionary([str(tmp_path / "absent.txt")])
        assert "password" in dictionary
