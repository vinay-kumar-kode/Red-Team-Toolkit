"""Email header analysis for phishing triage."""

from __future__ import annotations

import pytest
from redteam_toolkit.modules import phishing

PHISH = """\
From: "IT Service Desk" <it-support@paypa1-secure.com>
Reply-To: it-support@paypa1-secure.com
Return-Path: <bounce@mailer-paypa1-secure.com>
To: victim@company.com
Subject: [URGENT] Your account will be suspended - verify within 24 hours
Date: Tue, 03 Mar 2026 09:14:22 +0000
Message-ID: <20260303091422.abc123@mailer-paypa1-secure.com>
MIME-Version: 1.0
Authentication-Results: mx1.company.com; spf=fail smtp.mailfrom=mailer-paypa1-secure.com; dkim=none; dmarc=fail header.from=paypa1-secure.com
Received: from mx1.evil-hosting.net (mx1.evil-hosting.net [45.83.12.9])
 by mx2.company.com (Postfix) with ESMTPS id 4A2F1B2C
 for <victim@company.com>; Tue, 03 Mar 2026 09:14:20 +0000
Content-Type: text/html; charset=utf-8

<html><body>
<p>Your PayPal account has unusual activity. Act now to confirm your identity.</p>
<p><a href="https://secure.paypa1-secure.com/login?verify=1">verify now</a></p>
<p>Final notice: your account will be closed if you do not verify within 24 hours.</p>
</body></html>
"""

LEGIT = """\
From: "PayPal" <service@paypal.com>
Reply-To: service@paypal.com
Return-Path: <service@paypal.com>
To: victim@company.com
Subject: Your receipt
Date: Tue, 03 Mar 2026 10:00:00 +0000
Message-ID: <legit-1@paypal.com>
MIME-Version: 1.0
Authentication-Results: mx1.company.com; spf=pass smtp.mailfrom=paypal.com; dkim=pass header.d=paypal.com; dmarc=pass header.from=paypal.com
Received: from mail.paypal.com (mail.paypal.com [199.163.157.1])
 by mx2.company.com (Postfix) with ESMTPS id 9F2C
 for <victim@company.com>; Tue, 03 Mar 2026 10:00:01 +0000
Content-Type: text/plain; charset=utf-8

Your payment was processed. No action is needed.
"""

REPLY_MISMATCH = """\
From: "Payroll" <payroll@realcorp.com>
Reply-To: payroll@paypa1-verify.xyz
Subject: Action required: confirm your direct deposit
Date: Tue, 03 Mar 2026 10:00:00 +0000
Message-ID: <x@realcorp.com>
Authentication-Results: mx1.company.com; spf=pass; dkim=pass; dmarc=pass
Received: from mail.realcorp.com (mail.realcorp.com [1.2.3.4])
 by mx2.company.com; Tue, 03 Mar 2026 10:00:01 +0000

Please confirm.
"""


def write(tmp_path, text: str, name: str = "message.eml"):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return str(path)


class TestParsing:
    def test_headers_and_addresses(self, tmp_path):
        email = phishing.parse_email(write(tmp_path, PHISH))
        assert email.from_addr == "it-support@paypa1-secure.com"
        assert email.from_name == "IT Service Desk"
        assert email.from_domain == "paypa1-secure.com"
        assert email.reply_to == "it-support@paypa1-secure.com"
        assert email.return_path_domain == "mailer-paypa1-secure.com"

    def test_authentication_results_are_parsed(self, tmp_path):
        """Authentication-Results has to be read before the scheme verdicts."""
        email = phishing.parse_email(write(tmp_path, PHISH))
        assert email.spf_verdict == "fail"
        assert email.dkim_verdict == "none"
        assert email.dmarc_verdict == "fail"

    def test_passing_authentication_is_parsed(self, tmp_path):
        email = phishing.parse_email(write(tmp_path, LEGIT))
        assert email.spf_verdict == "pass"
        assert email.dkim_verdict == "pass"
        assert email.dmarc_verdict == "pass"

    def test_received_chain_is_counted(self, tmp_path):
        email = phishing.parse_email(write(tmp_path, PHISH))
        assert email.received_hosts
        assert "mx1.evil-hosting.net" in email.received_hosts[0]

    def test_body_urls_are_extracted(self, tmp_path):
        email = phishing.parse_email(write(tmp_path, PHISH))
        assert any("paypa1-secure.com/login" in url for url in email.body_urls)

    def test_missing_headers_are_absent_not_crashing(self, tmp_path):
        email = phishing.parse_email(write(tmp_path, "Subject: bare\n\nbody\n"))
        assert email.from_addr == ""
        assert email.spf_verdict == "absent"


class TestAnalysis:
    def test_phishing_message_has_critical_findings(self, tmp_path):
        report = phishing.analyse(write(tmp_path, PHISH))
        checks = {f.check for f in report.findings}
        assert "phish.dmarc-fail" in checks
        assert "phish.lookalike-domain" in checks
        assert report.at_or_above("critical")

    def test_legitimate_message_has_no_high_findings(self, tmp_path):
        """A clean message must stay clean, or the tool is noise."""
        report = phishing.analyse(write(tmp_path, LEGIT))
        assert not report.at_or_above("high"), [f.title for f in report.at_or_above("high")]

    def test_dmarc_pass_is_credited(self, tmp_path):
        report = phishing.analyse(write(tmp_path, LEGIT))
        assert any(f.check == "phish.dmarc-pass" for f in report.findings)

    def test_lookalike_domain_is_detected_by_normalisation(self, tmp_path):
        """paypa1-secure.com only reads as PayPal after leet normalisation."""
        report = phishing.analyse(write(tmp_path, PHISH))
        finding = next(f for f in report.findings if f.check == "phish.lookalike-domain")
        assert finding.evidence["claimed_brand"] == "paypal.com"
        assert finding.evidence["actual_domain"] == "paypa1-secure.com"

    def test_genuine_domain_is_not_flagged_as_lookalike(self, tmp_path):
        report = phishing.analyse(write(tmp_path, LEGIT))
        assert not any(f.check == "phish.lookalike-domain" for f in report.findings)

    def test_reply_to_mismatch_is_detected(self, tmp_path):
        report = phishing.analyse(write(tmp_path, REPLY_MISMATCH))
        finding = next(f for f in report.findings if f.check == "phish.reply-to-mismatch")
        assert finding.evidence["reply_to_domain"] == "paypa1-verify.xyz"

    def test_matching_reply_to_is_not_flagged(self, tmp_path):
        report = phishing.analyse(write(tmp_path, LEGIT))
        assert not any(f.check == "phish.reply-to-mismatch" for f in report.findings)

    def test_return_path_mismatch_is_detected(self, tmp_path):
        report = phishing.analyse(write(tmp_path, PHISH))
        assert any(f.check == "phish.return-path-mismatch" for f in report.findings)

    def test_urgency_pressure_is_detected(self, tmp_path):
        report = phishing.analyse(write(tmp_path, PHISH))
        finding = next(f for f in report.findings if f.check == "phish.urgency-pressure")
        assert len(finding.evidence["phrases"]) >= 2

    def test_calm_legitimate_message_has_no_urgency_finding(self, tmp_path):
        report = phishing.analyse(write(tmp_path, LEGIT))
        assert not any(f.check.startswith("phish.urgency") for f in report.findings)

    def test_single_link_is_noted(self, tmp_path):
        report = phishing.analyse(write(tmp_path, PHISH))
        assert any(f.check == "phish.single-link" for f in report.findings)

    def test_missing_file_is_reported(self, tmp_path):
        report = phishing.analyse(str(tmp_path / "absent.eml"))
        assert any(f.check == "phish.unreadable" for f in report.findings)


class TestUserinfoUrl:
    def test_credentials_before_the_real_host_is_critical(self, tmp_path):
        message = """\
From: "Bank" <alerts@evil.example>
Subject: Verify your account
Date: Tue, 03 Mar 2026 10:00:00 +0000
Message-ID: <x@evil.example>
Authentication-Results: mx1.company.com; dmarc=fail header.from=evil.example
Received: from mail.evil.example (mail.evil.example [1.2.3.4])
 by mx2.company.com; Tue, 03 Mar 2026 10:00:01 +0000

<a href="https://secure.realbank.com@evil.example/login">Verify</a>
"""
        report = phishing.analyse(write(tmp_path, message))
        finding = next(f for f in report.findings if f.check == "phish.userinfo-url")
        assert finding.severity == "critical"

    def test_ip_based_url_is_critical(self, tmp_path):
        message = """\
From: "Bank" <alerts@evil.example>
Subject: Verify
Date: Tue, 03 Mar 2026 10:00:00 +0000
Message-ID: <x@evil.example>
Authentication-Results: mx1.company.com; dmarc=fail header.from=evil.example
Received: from mail.evil.example (mail.evil.example [1.2.3.4])
 by mx2.company.com; Tue, 03 Mar 2026 10:00:01 +0000

<a href="http://203.0.113.99/login">Verify</a>
"""
        report = phishing.analyse(write(tmp_path, message))
        assert any(f.check == "phish.ip-url" for f in report.findings)


class TestAttachments:
    def _message(self, filename: str) -> str:
        import base64

        blob = base64.b64encode(b"fake attachment content").decode()
        return (
            "From: a@b.com\n"
            "Subject: Document\n"
            "Date: Tue, 03 Mar 2026 10:00:00 +0000\n"
            "Message-ID: <x@b.com>\n"
            "Authentication-Results: dmarc=pass\n"
            "Received: from mail.b.com (mail.b.com [1.2.3.4])\n"
            " by mx2.company.com; Tue, 03 Mar 2026 10:00:01 +0000\n"
            "MIME-Version: 1.0\n"
            'Content-Type: multipart/mixed; boundary="B"\n'
            "\n"
            "--B\n"
            "Content-Type: text/plain\n"
            "\n"
            "See attached.\n"
            "--B\n"
            f'Content-Type: application/octet-stream; name="{filename}"\n'
            "Content-Disposition: attachment; "
            f'filename="{filename}"\n'
            "Content-Transfer-Encoding: base64\n"
            "\n"
            f"{blob}\n"
            "--B--\n"
        )

    @pytest.mark.parametrize("filename", ["invoice.pdf.exe", "doc.docx.js", "x.ps1", "setup.iso"])
    def test_risky_attachments_are_flagged(self, tmp_path, filename: str):
        report = phishing.analyse(write(tmp_path, self._message(filename)))
        assert any(f.check == "phish.risky-attachment" for f in report.findings)

    def test_double_extension_is_critical(self, tmp_path):
        report = phishing.analyse(write(tmp_path, self._message("invoice.pdf.exe")))
        finding = next(f for f in report.findings if f.check == "phish.double-extension")
        assert finding.severity == "critical"

    def test_archive_attachment_is_medium(self, tmp_path):
        report = phishing.analyse(write(tmp_path, self._message("files.zip")))
        finding = next(f for f in report.findings if f.check == "phish.archive-attachment")
        assert finding.severity == "medium"

    def test_harmless_pdf_is_not_flagged(self, tmp_path):
        report = phishing.analyse(write(tmp_path, self._message("statement.pdf")))
        assert not any(f.check.startswith("phish.") and "attachment" in f.check for f in report.findings)


class TestBatch:
    def test_batch_summarises_risky_messages(self, tmp_path):
        (tmp_path / "a.eml").write_text(PHISH, encoding="utf-8")
        (tmp_path / "b.eml").write_text(LEGIT, encoding="utf-8")
        report = phishing.analyse_many(sorted(tmp_path.glob("*.eml")))
        assert report.data["messages_analysed"] == 2
        assert report.data["suspicious_count"] == 1
        assert report.data["suspicious"][0]["file"].endswith("a.eml")

    def test_clean_batch_is_reported_cleanly(self, tmp_path):
        (tmp_path / "b.eml").write_text(LEGIT, encoding="utf-8")
        report = phishing.analyse_many(sorted(tmp_path.glob("*.eml")))
        assert any(f.check == "phish.batch-clean" for f in report.findings)


class TestDomainNormalisation:
    @pytest.mark.parametrize(
        # "1" normalises to "l" and "4" to "a", which is the whole point: the
        # substituted domain collapses onto the brand it is imitating.
        "domain,expected",
        [
            ("paypa1-secure.com", "paypalsecurecom"),
            ("paypal.com", "paypalcom"),
            ("p4ypal.com", "paypalcom"),
            ("pay-pal.com", "paypalcom"),
        ],
    )
    def test_squeeze_domain(self, domain: str, expected: str):
        assert phishing._squeeze_domain(domain) == expected

    def test_lookalike_detection_uses_normalisation(self):
        assert "paypal" in phishing._squeeze_domain("paypa1-secure.com")
        assert "paypal" in phishing._squeeze_domain("p4ypal-secure.com")
