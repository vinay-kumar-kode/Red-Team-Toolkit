"""Port scanning, banner capture and service identification."""

from __future__ import annotations

import pytest
from redteam_toolkit.modules import scanner
from redteam_toolkit.utils.net import parse_ports


class TestPortParsing:
    def test_single_port(self):
        assert parse_ports("22") == [22]

    def test_comma_list_is_sorted_and_deduped(self):
        assert parse_ports("443,22,80,22") == [22, 80, 443]

    def test_range(self):
        assert parse_ports("8000-8003") == [8000, 8001, 8002, 8003]

    def test_mixed_list_and_range(self):
        assert parse_ports("22,80,8000-8001") == [22, 80, 8000, 8001]

    def test_whitespace_tolerated(self):
        assert parse_ports("22, 80 , 443") == [22, 80, 443]

    def test_none_and_empty_use_the_default(self):
        assert parse_ports(None, (22, 80)) == [22, 80]
        assert parse_ports("", (443,)) == [443]

    def test_list_input_is_accepted(self):
        assert parse_ports([443, 22, 22]) == [22, 443]

    @pytest.mark.parametrize("spec", ["0", "65536", "22-70000", "abc", "22-", "not-a-port"])
    def test_invalid_input_is_rejected(self, spec: str):
        with pytest.raises(ValueError):
            parse_ports(spec)

    def test_reversed_range_is_rejected(self):
        with pytest.raises(ValueError):
            parse_ports("100-50")

    def test_absurdly_wide_range_is_rejected(self):
        with pytest.raises(ValueError):
            parse_ports("1-65000")


class TestBannerHelpers:
    def test_version_is_extracted_from_an_ssh_banner(self):
        """The software version, not the SSH protocol version."""
        banner = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
        version = scanner.probe.__globals__["_version_from_product"](banner)
        assert version == "8.9p1"

    def test_product_is_extracted(self):
        extract = scanner.probe.__globals__["_extract_product"]
        assert extract("SSH-2.0-OpenSSH_8.9p1") == "OpenSSH"
        assert extract("220 vsftpd 2.3.4 ready") == "vsftpd"
        assert extract("HTTP/1.1 200 OK\r\nServer: nginx/1.18.0") == "nginx"

    def test_greeting_identifies_a_service_on_an_unregistered_port(self, banner_server):
        """SSH, FTP and MySQL all greet before being spoken to."""
        record = scanner.probe("127.0.0.1", banner_server.port, timeout=2.0)
        assert record["service"] == "SSH"

    def test_greeting_read_is_suppressed_by_no_banners(self, banner_server):
        record = scanner.probe("127.0.0.1", banner_server.port, timeout=2.0, grab_banner=False)
        assert record["service"] == "unknown"
        assert record["banner"] is None

    def test_product_extraction_returns_none_for_noise(self):
        extract = scanner.probe.__globals__["_extract_product"]
        assert extract("") is None
        assert extract("\x00\x01\x02binary") is None

    def test_version_extraction_handles_missing_pattern(self):
        extract = scanner.probe.__globals__["_extract_version"]
        assert extract("no version here", "") is None


class TestProbeAgainstClosedPort:
    def test_refused_connection_is_closed_not_filtered(self, closed_port: int):
        """The distinction matters: refused means the host answered, filtered means a firewall dropped."""
        record = scanner.probe("127.0.0.1", closed_port, timeout=0.5)
        assert record["state"] == "closed"
        assert record["port"] == closed_port

    def test_probe_never_raises_on_a_dead_address(self):
        record = scanner.probe("127.0.0.1", 1, timeout=0.2)
        assert record["state"] in ("closed", "filtered", "error")


@pytest.mark.network
class TestProbeAgainstLiveServer:
    def test_open_port_is_detected(self, http_server):
        record = scanner.probe("127.0.0.1", http_server.port, timeout=2.0)
        assert record["state"] == "open"
        assert record["port"] == http_server.port

    def test_banner_is_captured(self, banner_server):
        record = scanner.probe("127.0.0.1", banner_server.port, timeout=2.0)
        assert record["state"] == "open"
        assert "SSH-2.0-OpenSSH" in record["banner"]
        assert record["version"].startswith("8.9")
        assert record["product"] == "OpenSSH"

    def test_http_auto_detection_on_an_unregistered_port(self, http_server):
        """Lab web apps run on odd ports, and a missed one is a missed finding."""
        record = scanner.probe("127.0.0.1", http_server.port, timeout=2.0)
        assert record["service"] == "HTTP-unknown-port"
        assert "HTTP/" in record["banner"]

    def test_http_detection_can_be_disabled(self, http_server):
        record = scanner.probe("127.0.0.1", http_server.port, timeout=2.0, http_detect=False)
        assert record["service"] == "unknown"


@pytest.mark.network
class TestScanReport:
    def test_report_separates_states_and_lists_open_ports(self, http_server, closed_port):
        report = scanner.scan(
            "127.0.0.1",
            "127.0.0.1",
            ports=f"{http_server.port},{closed_port}",
            timeout=2.0,
        )
        assert http_server.port in report.data["open_ports"]
        assert closed_port in report.data["closed_ports"]
        assert len(report.data["ports"]) == 2

    def test_no_open_ports_produces_an_info_finding_not_an_error(self, closed_port):
        report = scanner.scan("127.0.0.1", "127.0.0.1", ports=str(closed_port), timeout=0.5)
        checks = {f.check for f in report.findings}
        assert checks == {"net.no-open-ports"}
        assert report.severity == "info"

    def test_unlisted_http_port_is_reported(self, http_server):
        report = scanner.scan("127.0.0.1", "127.0.0.1", ports=str(http_server.port), timeout=2.0)
        assert any(f.check == "net.web-on-unlisted-port" for f in report.findings)

    def test_report_is_json_serialisable(self, http_server):
        import json

        report = scanner.scan("127.0.0.1", "127.0.0.1", ports=str(http_server.port), timeout=2.0)
        assert json.loads(report.to_json())["module"] == "scanner"

    def test_duration_is_recorded(self, http_server):
        report = scanner.scan("127.0.0.1", "127.0.0.1", ports=str(http_server.port), timeout=2.0)
        assert report.duration_seconds > 0

    def test_banner_can_be_suppressed(self, banner_server):
        report = scanner.scan(
            "127.0.0.1",
            "127.0.0.1",
            ports=str(banner_server.port),
            timeout=2.0,
            grab_banners=False,
        )
        entry = report.data["ports"][0]
        assert entry["state"] == "open"
        assert entry["banner"] is None


class TestConcurrencySafety:
    def test_many_ports_do_not_exhaust_descriptors(self, closed_port: int):
        """A scan must not leak sockets; a leak shows up as EMFILE or a hung run."""
        ports = ",".join(str(closed_port + offset) for offset in range(1, 120))
        report = scanner.scan("127.0.0.1", "127.0.0.1", ports=ports, timeout=0.2, workers=32)
        assert len(report.data["ports"]) == 119
        assert not report.data["open_ports"]


class TestSocketHygiene:
    def test_descriptor_count_does_not_grow_across_probes(self, closed_port: int):
        def open_fds() -> int:
            import os
            from pathlib import Path

            fd_dir = Path(f"/proc/{os.getpid()}/fd")
            return len(list(fd_dir.iterdir())) if fd_dir.is_dir() else -1

        before = open_fds()
        for _ in range(40):
            scanner.probe("127.0.0.1", closed_port, timeout=0.2)
        after = open_fds()
        if before >= 0:
            assert after <= before + 2
