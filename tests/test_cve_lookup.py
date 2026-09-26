"""Offline CVE matching, version comparison and product normalisation."""

from __future__ import annotations

import pytest
from redteam_toolkit.modules import cve_lookup


class TestVersionParsing:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("2.4.29", (2, 4, 29)),
            ("2.4", (2, 4)),
            ("8.9p1", (8, 9)),
            ("5.3.29-1ubuntu2", (5, 3, 29)),
            ("1.0.30", (1, 0, 30)),
            ("7.2.24", (7, 2, 24)),
            ("20.04.3", (20, 4, 3)),
        ],
    )
    def test_numeric_extraction(self, raw: str, expected: tuple):
        assert cve_lookup.parse_version(raw) == expected

    def test_unparseable_version_is_empty(self):
        assert cve_lookup.parse_version("no digits here") == ()
        assert cve_lookup.parse_version("") == ()


class TestVersionRanges:
    @pytest.mark.parametrize(
        "version,start,end,expected",
        [
            ("2.4.49", "2.4.49", "2.4.50", True),
            ("2.4.29", "2.4.49", "2.4.50", False),
            ("2.4.51", "2.4.49", "2.4.50", False),
            ("8.9p1", "8.5p1", "9.7p1", True),
            ("9.8p1", "8.5p1", "9.7p1", False),
            ("1.0.30", "0.6.18", "1.20.0", True),
            ("5.3.29", "5.3.0", "5.3.17", False),
            ("5.3.10", "5.3.0", "5.3.17", True),
            # Short versions must not be rejected against longer ranges.
            ("2.4", "2.4.0", "2.4.38", True),
        ],
    )
    def test_range_membership(self, version: str, start: str, end: str, expected: bool):
        assert cve_lookup.version_in_range(version, start, end) is expected

    def test_unparseable_version_never_matches(self):
        assert cve_lookup.version_in_range("unknown", "2.4.0", "2.4.38") is False
        assert cve_lookup.version_in_range("2.4.29", "x", "y") is False


class TestProductNormalisation:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("Apache/2.4.29 (Ubuntu)", "apache http server"),
            ("Apache/2.4.49", "apache http server"),
            ("apache2", "apache http server"),
            ("OpenSSH_8.9p1", "openssh"),
            ("OpenSSH 7.4", "openssh"),
            ("nginx/1.18.0", "nginx"),
            ("vsftpd 2.3.4", "vsftpd"),
            ("PHP/7.2.24", "php"),
            ("log4j-core-2.14.1", "log4j"),
            ("redis-server", "redis"),
            ("Tomcat/9.0.30", "apache tomcat"),
        ],
    )
    def test_normalisation(self, raw: str, expected: str):
        assert cve_lookup.normalise_product(raw) == expected

    def test_empty_input(self):
        assert cve_lookup.normalise_product("") == ""


class TestLookup:
    def test_known_vulnerable_version_matches(self):
        matches = cve_lookup.lookup("Apache HTTP Server", "2.4.49")
        ids = {m.cve_id for m in matches}
        assert "CVE-2021-41773" in ids
        assert "CVE-2021-42013" in ids

    def test_patched_version_does_not_match(self):
        matches = cve_lookup.lookup("Apache HTTP Server", "2.4.51")
        assert not [m for m in matches if m.cve_id.startswith("CVE-2021-4")]

    def test_alias_is_used_when_the_key_does_not_match(self):
        by_name = cve_lookup.lookup("Apache HTTP Server", "2.4.49")
        by_alias = cve_lookup.lookup("apache2", "2.4.49")
        assert {m.cve_id for m in by_name} == {m.cve_id for m in by_alias}

    def test_results_are_sorted_by_cvss(self):
        matches = cve_lookup.lookup("log4j-core", "2.14.1")
        scores = [m.cvss for m in matches]
        assert scores == sorted(scores, reverse=True)
        assert matches[0].cve_id == "CVE-2021-44228"

    def test_one_match_per_cve_even_with_multiple_ranges(self):
        matches = cve_lookup.lookup("PHP", "8.1.15")
        ids = [m.cve_id for m in matches]
        assert len(ids) == len(set(ids))

    def test_unknown_product_returns_empty_not_an_error(self):
        assert cve_lookup.lookup("SomeCustomProduct", "1.2.3") == []

    def test_missing_version_returns_empty(self):
        assert cve_lookup.lookup("Apache HTTP Server", "") == []

    def test_match_carries_remediation(self):
        matches = cve_lookup.lookup("vsftpd", "2.3.4")
        assert matches
        assert all(m.remediation for m in matches)

    def test_database_declares_itself_a_subset(self):
        database = cve_lookup.load_database()
        assert "curated" in database["disclaimer"].lower()
        assert "NVD" in database["disclaimer"]


class TestDatabaseIntegrity:
    """The shipped database is the tool's core data, so validate its shape."""

    @pytest.fixture(scope="class")
    @classmethod
    def database(cls):
        """Loaded once per class; the JSON is read-only and cheap to share."""
        return cve_lookup.load_database()

    def test_every_cve_entry_is_well_formed(self, database):
        required = {"id", "affected", "severity", "cvss", "summary", "remediation"}
        for product, entry in database["products"].items():
            for cve in entry.get("cves", []):
                missing = required - set(cve)
                assert not missing, f"{product} {cve.get('id')} missing {missing}"
                assert cve["id"].startswith("CVE-")
                assert cve["severity"] in ("critical", "high", "medium", "low")
                assert 0 <= cve["cvss"] <= 10
                assert len(cve["affected"]) >= 1

    def test_every_affected_range_is_two_versions(self, database):
        for entry in database["products"].values():
            for cve in entry.get("cves", []):
                for pair in cve["affected"]:
                    assert len(pair) == 2, f"{cve['id']}: {pair}"
                    assert cve_lookup.parse_version(pair[0]), f"{cve['id']}: {pair[0]}"
                    assert cve_lookup.parse_version(pair[1]), f"{cve['id']}: {pair[1]}"

    def test_every_range_is_ordered(self, database):
        for entry in database["products"].values():
            for cve in entry.get("cves", []):
                for start, end in cve["affected"]:
                    low = cve_lookup.parse_version(start)
                    high = cve_lookup.parse_version(end)
                    padded_low = low + (0,) * (max(len(low), len(high)) - len(low))
                    padded_high = high + (0,) * (max(len(low), len(high)) - len(high))
                    assert padded_low <= padded_high, f"{cve['id']}: {start}-{end}"

    def test_cve_ids_are_unique(self, database):
        ids = [cve["id"] for entry in database["products"].values() for cve in entry.get("cves", [])]
        assert len(ids) == len(set(ids))

    def test_products_without_cves_are_absent(self, database):
        """An empty product entry is a data-entry mistake, not a feature."""
        empty = [name for name, entry in database["products"].items() if not entry.get("cves")]
        assert not empty, f"products with no CVEs: {empty}"

    def test_every_product_has_an_alias_list(self, database):
        for name, entry in database["products"].items():
            assert "aliases" in entry, name


class TestReport:
    def test_matches_become_findings(self):
        report = cve_lookup.lookup_report([("Apache HTTP Server", "2.4.49")])
        assert report.at_or_above("critical")
        finding = report.findings[0]
        assert "CVE-2021-41773" in finding.evidence["cves"]

    def test_no_matches_is_information_not_reassurance(self):
        """Silence must never read as "safe"."""
        report = cve_lookup.lookup_report([("Apache HTTP Server", "2.4.51")])
        finding = next(f for f in report.findings if f.check == "cve.no-matches")
        assert finding.severity == "info"
        assert "not proof" in finding.detail

    def test_uncovered_product_is_reported(self):
        report = cve_lookup.lookup_report([("MyCustomAppliance", "3.1")])
        assert any(f.check == "cve.uncovered-product" for f in report.findings)

    def test_missing_database_is_reported(self, tmp_path):
        report = cve_lookup.lookup_report([("x", "1")], db_path=str(tmp_path / "absent.json"))
        assert any(f.check == "cve.db-missing" for f in report.findings)

    def test_report_records_the_database_provenance(self):
        report = cve_lookup.lookup_report([("Apache HTTP Server", "2.4.49")])
        assert report.data["db_version"]
        assert report.data["cves_in_db"] > 0

    def test_report_serialises(self):
        import json

        json.loads(cve_lookup.lookup_report([("Apache HTTP Server", "2.4.49")]).to_json())


class TestScanIntegration:
    def test_observations_are_extracted_from_a_scan_report(self):
        from redteam_toolkit.models import Report

        scan = Report(module="scanner", target="t")
        scan.data["ports"] = [
            {"port": 22, "state": "open", "service": "SSH", "product": "OpenSSH_8.9p1", "version": "8.9p1"},
            {
                "port": 443,
                "state": "open",
                "service": "HTTPS",
                "product": "HTTPS (TLS, banner encrypted)",
                "version": None,
            },
            {"port": 80, "state": "closed", "service": "HTTP", "product": None, "version": None},
        ]
        observations = cve_lookup.from_scan_report(scan)
        assert ("OpenSSH_8.9p1", "8.9p1") in observations
        # Closed ports and TLS-only placeholders carry no version to match on.
        assert all("HTTPS" not in product for product, _version in observations)

    def test_scan_versions_flow_into_cve_lookup(self):
        from redteam_toolkit.models import Report

        scan = Report(module="scanner", target="t")
        scan.data["ports"] = [
            {"port": 80, "state": "open", "service": "HTTP", "product": "Apache/2.4.49", "version": "2.4.49"}
        ]
        report = cve_lookup.lookup_report(cve_lookup.from_scan_report(scan))
        assert report.at_or_above("critical")
