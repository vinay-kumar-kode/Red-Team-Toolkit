"""Report models, and the text / JSON / HTML renderers."""

from __future__ import annotations

import json
import re

import pytest
from redteam_toolkit.models import Finding, Report, Timer, severity_rank
from redteam_toolkit.reporting import Bundle, render_html, render_text, write_bundle
from redteam_toolkit.utils import console


def make_report(module: str = "test", target: str = "127.0.0.1") -> Report:
    report = Report(module=module, target=target)
    report.add("test.critical", "Critical thing", "critical", "It is very bad.", "Fix it now.", port=22)
    report.add("test.high", "High thing", "high", "Quite bad.", "Fix it.", port=80)
    report.add("test.medium", "Medium thing", "medium", "Somewhat bad.", "Consider it.", port=443)
    report.add("test.low", "Low thing", "low", "Minor.", "Optional.", port=8080)
    report.add("test.info", "Info thing", "info", "For context.", "No action.", port=22)
    return report


class TestReportModel:
    def test_severity_is_the_highest_finding(self):
        assert make_report().severity == "critical"

    def test_empty_report_is_info(self):
        assert Report(module="m", target="t").severity == "info"

    def test_counts_cover_every_level(self):
        counts = make_report().counts
        assert counts == {"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1}

    def test_findings_sort_most_severe_first(self):
        severities = [f.severity for f in make_report().sorted_findings()]
        assert severities == sorted(severities, key=severity_rank, reverse=True)

    def test_at_or_above_filters_by_severity(self):
        report = make_report()
        assert len(report.at_or_above("high")) == 2
        assert len(report.at_or_above("medium")) == 3
        assert len(report.at_or_above("info")) == 5

    def test_evidence_is_preserved(self):
        finding = make_report().findings[0]
        assert finding.evidence == {"port": 22}
        assert finding.to_dict()["evidence"] == {"port": 22}

    def test_duration_is_recorded_by_the_timer(self):
        report = Report(module="m", target="t")
        with Timer(report):
            sum(range(100_000))
        assert report.duration_seconds > 0

    def test_json_round_trip(self):
        report = make_report()
        restored = json.loads(report.to_json())
        assert restored["module"] == "test"
        assert len(restored["findings"]) == 5
        assert restored["severity"] == "critical"

    def test_unknown_severity_sorts_lowest(self):
        assert severity_rank("bogus") == -1

    def test_finding_dataclass_fields(self):
        finding = Finding(check="c", title="t", severity="low")
        assert finding.detail == ""
        assert finding.remediation == ""
        assert finding.evidence == {}


class TestBundle:
    @pytest.fixture
    def bundle(self) -> Bundle:
        b = Bundle(command="test")
        b.add(make_report("scanner"))
        b.add(make_report("webscan", "http://127.0.0.1/"))
        return b

    def test_aggregate_counts(self, bundle: Bundle):
        assert bundle.counts["critical"] == 2
        assert len(bundle.findings) == 10

    def test_severity_is_aggregate(self, bundle: Bundle):
        assert bundle.severity == "critical"

    def test_flattened_findings_carry_their_module(self, bundle: Bundle):
        data = bundle.to_dict()
        assert len(data["findings"]) == 10
        assert {f["module"] for f in data["findings"]} == {"scanner", "webscan"}

    def test_flattened_findings_are_sorted(self, bundle: Bundle):
        severities = [severity_rank(f["severity"]) for f in bundle.to_dict()["findings"]]
        assert severities == sorted(severities, reverse=True)

    def test_at_or_above_across_modules(self, bundle: Bundle):
        assert len(bundle.at_or_above("high")) == 4

    def test_json_is_valid(self, bundle: Bundle):
        data = json.loads(bundle.to_json())
        assert data["tool"]["name"] == "Red Team Toolkit"
        assert len(data["reports"]) == 2


class TestTextRendering:
    def test_render_contains_module_and_findings(self):
        report = make_report()
        text = render_text(BundleWith(report).bundle)
        assert report.module in text
        assert "Critical thing" in text
        assert "Fix it now." in text

    def test_render_says_so_when_clean(self):
        report = Report(module="clean", target="t")
        text = render_text(BundleWith(report).bundle)
        assert "No findings" in text

    def test_render_includes_data(self):
        report = Report(module="m", target="t")
        report.data["open_ports"] = [22, 80]
        text = render_text(BundleWith(report).bundle)
        assert "open_ports" in text
        assert "22" in text

    def test_render_is_colourless(self):
        """A written .txt report must not contain escape sequences."""
        text = render_text(BundleWith(make_report()).bundle, color=False)
        assert "\033[" not in text

    def test_render_handles_nested_data(self):
        report = Report(module="m", target="t")
        report.data["nested"] = {"a": 1, "b": "two"}
        report.data["items"] = [{"port": 22}, {"port": 80}]
        text = render_text(BundleWith(report).bundle)
        assert "nested.a" in text
        assert "items" in text


class TestHtmlRendering:
    def test_is_a_complete_self_contained_document(self):
        html = render_html(BundleWith(make_report()).bundle)
        assert html.startswith("<!doctype html>")
        assert html.rstrip().endswith("</html>")

    def test_makes_no_external_requests(self):
        """A report gets emailed; it must not phone home when opened."""
        html = render_html(BundleWith(make_report()).bundle)
        assert "http://" not in html.replace("http://www.w3.org", "")
        assert "<script src" not in html
        assert "<link" not in html

    def test_inlines_its_own_stylesheet_and_script(self):
        html = render_html(BundleWith(make_report()).bundle)
        assert "<style>" in html
        assert "<script>" in html

    def test_escapes_finding_text(self):
        report = Report(module="m", target="t")
        report.add("x", "<script>alert('xss')</script>", "high", "<img src=x onerror=alert(1)>")
        html = render_html(BundleWith(report).bundle)
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html

    def test_includes_counts_and_severities(self):
        html = render_html(BundleWith(make_report()).bundle)
        for severity in ("critical", "high", "medium", "low", "info"):
            assert f">{severity}</div>" in html

    def test_filter_buttons_appear_only_when_there_are_findings(self):
        with_findings = render_html(BundleWith(make_report()).bundle)
        assert 'data-sev="critical"' in with_findings

        clean = Report(module="clean", target="t")
        assert "data-sev=" not in render_html(BundleWith(clean).bundle)

    def test_every_finding_renders_with_a_remediation(self):
        html = render_html(BundleWith(make_report()).bundle)
        assert html.count('class="finding ') == 5
        assert "Fix it now." in html

    def test_clean_report_says_so(self):
        clean = Report(module="clean", target="t")
        assert "No findings in this module" in render_html(BundleWith(clean).bundle)

    def test_long_data_lists_are_capped(self):
        report = Report(module="m", target="t")
        report.data["many"] = [f"item-{i}" for i in range(200)]
        html = render_html(BundleWith(report).bundle)
        assert "item-49" in html
        assert "item-199" not in html


class TestWriting:
    def test_all_formats_are_written(self, tmp_path):
        bundle = BundleWith(make_report()).bundle
        written = write_bundle(bundle, output_dir=tmp_path, formats=("json", "html", "txt"))
        assert len(written) == 3
        assert all(path.is_file() and path.stat().st_size > 0 for path in written)

    def test_written_json_is_parseable(self, tmp_path):
        bundle = BundleWith(make_report()).bundle
        path = write_bundle(bundle, output_dir=tmp_path, formats=("json",))[0]
        assert json.loads(path.read_text())["tool"]["version"]

    def test_basename_is_honoured(self, tmp_path):
        bundle = BundleWith(make_report()).bundle
        path = write_bundle(bundle, output_dir=tmp_path, basename="fixed", formats=("json",))[0]
        assert path.name == "fixed.json"

    def test_output_directory_is_created(self, tmp_path):
        target = tmp_path / "nested" / "deeper"
        bundle = BundleWith(make_report()).bundle
        write_bundle(bundle, output_dir=target, formats=("json",))
        assert target.is_dir()

    def test_unknown_format_is_rejected(self, tmp_path):
        with pytest.raises(ValueError, match="unknown report format"):
            write_bundle(BundleWith(make_report()).bundle, output_dir=tmp_path, formats=("pdf",))

    def test_default_directory_respects_the_environment(self, tmp_path, monkeypatch):
        monkeypatch.setenv("RTT_OUTDIR", str(tmp_path / "env-out"))
        bundle = BundleWith(make_report()).bundle
        write_bundle(bundle, formats=("json",))
        assert (tmp_path / "env-out").is_dir()


class BundleWith:
    """Small adapter so the render functions can be called with one report."""

    def __init__(self, report: Report) -> None:
        self.bundle = Bundle(command=report.module)
        self.bundle.add(report)


class TestConsole:
    def test_quiet_mode_suppresses_output(self, capsys):
        console.set_quiet(True)
        try:
            console.info("should not appear")
            console.table(["a"], [["b"]])
            console.header("title")
        finally:
            console.set_quiet(False)
        captured = capsys.readouterr()
        assert captured.out == ""

    def test_no_color_override_wins_over_the_environment(self, monkeypatch):
        monkeypatch.setenv("FORCE_COLOR", "1")
        console.set_color(False)
        try:
            assert console.resolve() is False
        finally:
            console.set_color(None)

    def test_explicit_force_beats_the_override(self):
        console.set_color(False)
        try:
            assert console.resolve(True) is True
        finally:
            console.set_color(None)

    def test_table_respects_the_terminal_width(self, capsys):
        console.set_quiet(False)
        console.set_color(False)
        rows = [["x" * 200, "y" * 200]]
        console.table(["col-a", "col-b"], rows)
        captured = capsys.readouterr()
        for line in captured.out.splitlines():
            visible = re.sub(r"\033\[[0-9;]*m", "", line)
            assert len(visible) <= 105, len(visible)

    def test_paint_is_a_no_op_without_color(self):
        assert console.paint("x", "bold") == "x" or "\033" not in console.paint("x", "bold")

    def test_errors_go_to_stderr_even_when_quiet(self, capsys):
        console.set_quiet(True)
        try:
            console.error("boom")
        finally:
            console.set_quiet(False)
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "boom" in captured.err
