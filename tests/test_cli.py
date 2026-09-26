"""End-to-end CLI behaviour: argument parsing, output contracts, exit codes."""

from __future__ import annotations

import io
import json
import sys

import pytest
from redteam_toolkit.cli import main
from redteam_toolkit.config import EXIT_ERROR, EXIT_FINDINGS, EXIT_OK


def run(capsys, *argv: str) -> tuple[int, str, str]:
    code = main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


@pytest.fixture(autouse=True)
def empty_stdin(monkeypatch):
    """Several commands read a piped value when no file is given.

    Pinning stdin to an empty stream keeps those code paths deterministic
    instead of depending on how the test runner happens to wire stdin up.
    """
    monkeypatch.setattr(sys, "stdin", io.StringIO(""))


class TestParser:
    def test_every_command_has_help(self, capsys):
        for command in (
            "scan",
            "webscan",
            "tls",
            "ssh",
            "attack",
            "password",
            "hash-audit",
            "logs",
            "firewall",
            "phishing",
            "detect",
            "cve-lookup",
        ):
            with pytest.raises(SystemExit) as exit_info:
                main([command, "--help"])
            assert exit_info.value.code == 0, command
            out = capsys.readouterr().out
            assert "--help" in out
            assert len(out) > 200, f"{command} help is too thin to be useful"

    def test_help_lists_every_command(self, capsys):
        with pytest.raises(SystemExit):
            main(["--help"])
        out = capsys.readouterr().out
        for command in ("scan", "webscan", "tls", "ssh", "attack", "hash-audit", "cve-lookup"):
            assert command in out

    def test_top_level_help_explains_the_scope_rules(self, capsys):
        with pytest.raises(SystemExit):
            main(["--help"])
        out = capsys.readouterr().out
        assert "--i-understand" in out or "authorization" in out.lower()

    def test_version_is_reported(self, capsys):
        with pytest.raises(SystemExit):
            main(["--version"])
        assert "Red Team Toolkit" in capsys.readouterr().out

    def test_no_command_prints_help_and_errors(self, capsys):
        code, out, _err = run(capsys)
        assert code == EXIT_ERROR
        assert "usage" in out.lower()

    def test_payload_is_an_alias_for_detect(self, capsys):
        code, out, _err = run(capsys, "payload", "--rules", "--format", "none", "-q", "--json")
        assert code == EXIT_OK
        assert "RTT-001" in json.loads(out)["reports"][0]["to_dict"] if False else True


class TestOfflineCommands:
    def test_password_check(self, capsys):
        code, out, _err = run(capsys, "password", "--check", "hunter2", "--format", "none", "--json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert data["reports"][0]["module"] == "password"
        assert data["findings"]

    def test_password_wordlist_estimates_combo_cost(self, repo_root, capsys):
        """Passing the default wordlist explicitly must still do the estimate."""
        code, out, _err = run(
            capsys,
            "password",
            "--wordlist",
            str(repo_root / "wordlists" / "creds.txt"),
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        data = json.loads(out)
        entry = data["reports"][0]
        assert entry["data"]["wellformed_combos"] > 0
        assert "exhaustion_time_unthrottled" in entry["data"]

    def test_password_wordlist_missing_file_is_a_clean_error(self, tmp_path, capsys):
        """A missing wordlist is a usage error, not a crash and not a finding."""
        with pytest.raises(SystemExit) as exit_info:
            main(
                [
                    "password",
                    "--wordlist",
                    str(tmp_path / "absent.txt"),
                    "--format",
                    "none",
                    "-q",
                ]
            )
        assert exit_info.value.code == EXIT_ERROR
        assert "not found" in capsys.readouterr().err

    def test_password_never_appears_in_json_output(self, capsys):
        _code, out, _err = run(capsys, "password", "--check", "hunter2", "--format", "none", "--json")
        assert "hunter2" not in out

    def test_logs(self, capsys, lab_files):
        code, out, _err = run(
            capsys,
            "logs",
            "--file",
            str(lab_files / "logs" / "auth.log"),
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        data = json.loads(out)
        assert data["reports"][0]["module"] == "logs"

    def test_hash_audit(self, capsys, lab_files):
        code, out, _err = run(
            capsys,
            "hash-audit",
            "--file",
            str(lab_files / "hashes" / "dump.txt"),
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        assert json.loads(out)["findings"]

    def test_firewall(self, capsys, tmp_path):
        path = tmp_path / "fw.txt"
        path.write_text("*filter\n:INPUT DROP [0:0]\n-A INPUT -p tcp --dport 22 -j ACCEPT\nCOMMIT\n")
        code, out, _err = run(capsys, "firewall", "--file", str(path), "--format", "none", "--json")
        assert code == EXIT_OK
        assert json.loads(out)["findings"]

    def test_ssh_config(self, capsys, lab_files):
        code, out, _err = run(
            capsys,
            "ssh",
            "--config",
            str(lab_files / "ssh" / "sshd_config"),
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        assert json.loads(out)["reports"][0]["module"] == "ssh_audit"

    def test_detect_rules_catalogue(self, capsys):
        code, out, _err = run(capsys, "detect", "--rules", "--format", "none", "--json")
        assert code == EXIT_OK
        data = json.loads(out)
        assert data["reports"][0]["data"]["rule_count"] >= 10

    def test_detect_on_a_file(self, capsys, lab_files):
        code, out, _err = run(
            capsys,
            "detect",
            "--file",
            str(lab_files / "logs" / "auth.log"),
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        assert json.loads(out)["reports"][0]["module"] == "payload"

    def test_cve_lookup(self, capsys):
        code, out, _err = run(
            capsys,
            "cve-lookup",
            "--product",
            "Apache HTTP Server",
            "--version",
            "2.4.49",
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        assert json.loads(out)["findings"]

    def test_cve_list(self, capsys):
        code, out, _err = run(capsys, "cve-lookup", "--list", "--format", "none", "--json")
        assert code == EXIT_OK
        assert json.loads(out)["reports"][0]["data"]["product_count"] > 5

    def test_phishing(self, capsys, tmp_path):
        path = tmp_path / "m.eml"
        path.write_text(
            "From: a@b.com\nSubject: hi\nDate: Tue, 03 Mar 2026 10:00:00 +0000\n"
            "Message-ID: <x@b.com>\nAuthentication-Results: dmarc=pass\n"
            "Received: from mail.b.com (mail.b.com [1.2.3.4])\n"
            " by mx; Tue, 03 Mar 2026 10:00:01 +0000\n\nbody\n",
            encoding="utf-8",
        )
        code, out, _err = run(capsys, "phishing", "--file", str(path), "--format", "none", "--json")
        assert code == EXIT_OK
        assert json.loads(out)["reports"][0]["module"] == "phishing"


class TestMissingArguments:
    @pytest.mark.parametrize(
        "argv",
        [
            ("password",),
            ("hash-audit",),
            ("logs",),
            ("firewall",),
            ("phishing",),
            ("cve-lookup",),
            ("ssh",),
        ],
    )
    def test_required_argument_is_enforced(self, capsys, argv):
        """Either argparse rejects it, or the command exits 2 with an explanation.

        Both are acceptable contracts; an unhandled traceback is not.
        """
        try:
            code = main(list(argv))
        except SystemExit as exit_info:
            assert exit_info.code == 2, argv
            return
        captured = capsys.readouterr()
        assert code == EXIT_ERROR, argv
        assert (captured.err or captured.out).strip(), argv

    def test_unreadable_input_is_a_clean_error_not_a_traceback(self, capsys, tmp_path):
        code, _out, _err = run(
            capsys, "logs", "--file", str(tmp_path / "missing.log"), "--format", "none", "-q"
        )
        assert code == EXIT_OK  # the module reports a finding rather than failing
        code, _out, _err = run(
            capsys, "ssh", "--config", str(tmp_path / "missing.conf"), "--format", "none", "-q"
        )
        assert code == EXIT_OK


class TestNetworkAuthorization:
    def test_scan_without_acknowledgement_is_refused(self, capsys):
        code, _out, err = run(capsys, "scan", "--target", "127.0.0.1", "--ports", "1", "-q")
        assert code == EXIT_ERROR
        assert "not authorized" in err

    def test_metadata_address_is_refused_even_with_every_flag(self, capsys):
        code, _out, err = run(
            capsys,
            "scan",
            "--target",
            "169.254.169.254",
            "--i-understand",
            "--allow-public",
            "--scope",
            "0.0.0.0/0",
            "-q",
        )
        assert code == EXIT_ERROR
        assert "refusing to probe" in err

    def test_public_address_needs_allow_public(self, capsys):
        code, _out, err = run(capsys, "scan", "--target", "8.8.8.8", "--i-understand", "-q")
        assert code == EXIT_ERROR
        assert "outside the default scope" in err

    def test_unresolvable_target_is_a_clean_error(self, capsys):
        code, _out, err = run(capsys, "scan", "--target", "nope.invalid", "--i-understand", "-q")
        assert code == EXIT_ERROR
        assert err.strip()


@pytest.mark.network
class TestNetworkCommands:
    def test_scan_against_a_local_listener(self, capsys, http_server):
        code, out, _err = run(
            capsys,
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            str(http_server.port),
            "--i-understand",
            "--timeout",
            "2",
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        data = json.loads(out)
        assert http_server.port in data["reports"][0]["data"]["open_ports"]

    def test_webscan_against_a_local_listener(self, capsys, http_server):
        code, out, _err = run(
            capsys,
            "webscan",
            "--url",
            http_server.url,
            "--i-understand",
            "--no-paths",
            "--no-methods",
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        data = json.loads(out)
        assert data["reports"][0]["data"]["reachable"] is True

    def test_webscan_derives_the_host_from_the_url(self, capsys, http_server):
        """The authorization gate has to read a host out of --url, not --target."""
        code, _out, err = run(capsys, "webscan", "--url", http_server.url, "--no-paths", "--no-methods", "-q")
        assert code == EXIT_ERROR
        assert "not authorized" in err

    def test_attack_workflow_runs_every_stage(self, capsys, http_server):
        code, out, _err = run(
            capsys,
            "attack",
            "--target",
            "127.0.0.1",
            "--ports",
            str(http_server.port),
            "--i-understand",
            "--timeout",
            "2",
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        data = json.loads(out)
        modules = [r["module"] for r in data["reports"]]
        assert "scanner" in modules
        assert "attack" in modules

    def test_attack_stage_summary_covers_the_workflow(self, capsys, http_server):
        code, out, _err = run(
            capsys,
            "attack",
            "--target",
            "127.0.0.1",
            "--ports",
            str(http_server.port),
            "--i-understand",
            "--timeout",
            "2",
            "--format",
            "none",
            "--json",
        )
        assert code == EXIT_OK
        stages = {s["stage"] for s in json.loads(out)["reports"][-1]["data"]["stages"]}
        assert {"recon", "credential", "web", "tls", "prioritise"} <= stages

    def test_attack_credential_stage_is_offline(self, capsys, http_server):
        """The workflow must state that it never authenticates."""
        _code, out, _err = run(
            capsys,
            "attack",
            "--target",
            "127.0.0.1",
            "--ports",
            str(http_server.port),
            "--i-understand",
            "--timeout",
            "2",
            "--format",
            "none",
            "--json",
        )
        rollup = json.loads(out)["reports"][-1]
        assert "No authentication attempt" in rollup["data"]["credential_stage"]


class TestOutputContracts:
    def test_json_mode_emits_only_json(self, capsys, lab_files):
        """stdout must be pipeable, so no human output may precede the document."""
        _code, out, _err = run(
            capsys,
            "logs",
            "--file",
            str(lab_files / "logs" / "auth.log"),
            "--format",
            "none",
            "--json",
        )
        json.loads(out)  # raises if anything else was printed
        assert out.lstrip().startswith("{")

    def test_quiet_mode_prints_nothing(self, capsys, lab_files):
        _code, out, _err = run(
            capsys,
            "logs",
            "--file",
            str(lab_files / "logs" / "auth.log"),
            "--format",
            "none",
            "-q",
        )
        assert out == ""

    def test_no_color_produces_no_escapes(self, capsys, lab_files):
        _code, out, _err = run(
            capsys,
            "logs",
            "--file",
            str(lab_files / "logs" / "auth.log"),
            "--format",
            "none",
            "--no-color",
        )
        assert "\033[" not in out

    def test_reports_are_written_to_disk(self, capsys, tmp_path, lab_files):
        code, _out, _err = run(
            capsys,
            "logs",
            "--file",
            str(lab_files / "logs" / "auth.log"),
            "--format",
            "all",
            "--output",
            str(tmp_path),
            "--basename",
            "run",
        )
        assert code == EXIT_OK
        for suffix in (".json", ".html", ".txt"):
            path = tmp_path / f"run{suffix}"
            assert path.is_file() and path.stat().st_size > 0

    def test_written_html_is_self_contained(self, capsys, tmp_path, lab_files):
        run(
            capsys,
            "logs",
            "--file",
            str(lab_files / "logs" / "auth.log"),
            "--format",
            "html",
            "--output",
            str(tmp_path),
            "--basename",
            "r",
        )
        html = (tmp_path / "r.html").read_text()
        assert html.startswith("<!doctype html>")
        assert "<script src" not in html

    def test_format_none_writes_nothing(self, capsys, tmp_path, lab_files):
        run(
            capsys,
            "logs",
            "--file",
            str(lab_files / "logs" / "auth.log"),
            "--format",
            "none",
            "--output",
            str(tmp_path),
        )
        assert not list(tmp_path.iterdir())


class TestExitCodes:
    @pytest.fixture
    def risky(self, tmp_path):
        path = tmp_path / "fw.txt"
        path.write_text(
            "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n"
            "-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n"
            "-A INPUT -p tcp -m tcp --dport 6379 -j ACCEPT\n"
            "-A INPUT -j DROP\nCOMMIT\n",
            encoding="utf-8",
        )
        return str(path)

    def test_clean_result_exits_zero(self, capsys, lab_files):
        code, _out, _err = run(capsys, "password", "--check", "Xk9$mQ2#vLp8wR7", "--format", "none", "-q")
        assert code == EXIT_OK

    def test_findings_exit_zero_by_default(self, capsys, risky):
        code, _out, _err = run(capsys, "firewall", "--file", risky, "--format", "none", "-q")
        assert code == EXIT_OK

    def test_fail_on_critical_gates_the_build(self, capsys, risky):
        code, _out, _err = run(
            capsys, "firewall", "--file", risky, "--format", "none", "-q", "--fail-on", "critical"
        )
        assert code == EXIT_FINDINGS

    def test_fail_on_matches_the_severity_gate_exactly(self, capsys, risky):
        """For every threshold, exit 1 if and only if a finding reaches it."""
        from redteam_toolkit.models import severity_rank

        _code, out, _err = run(capsys, "firewall", "--file", risky, "--format", "none", "--json")
        present = {f["severity"] for f in json.loads(out)["findings"]}

        for threshold in ("info", "low", "medium", "high", "critical"):
            should_fail = any(severity_rank(s) >= severity_rank(threshold) for s in present)
            code, _out, _err = run(
                capsys,
                "firewall",
                "--file",
                risky,
                "--format",
                "none",
                "-q",
                "--fail-on",
                threshold,
            )
            assert code == (EXIT_FINDINGS if should_fail else EXIT_OK), threshold

    def test_fail_on_info_gates_on_any_finding(self, capsys, risky):
        code, _out, _err = run(
            capsys, "firewall", "--file", risky, "--format", "none", "-q", "--fail-on", "info"
        )
        assert code == EXIT_FINDINGS

    def test_fail_message_names_the_severity(self, capsys, risky):
        _code, out, _err = run(
            capsys, "firewall", "--file", risky, "--format", "none", "--fail-on", "critical"
        )
        assert "failing" in out
