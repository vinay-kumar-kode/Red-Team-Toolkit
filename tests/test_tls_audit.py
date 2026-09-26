"""TLS configuration and certificate auditing against a local TLS server."""

from __future__ import annotations

import socket
import ssl
import threading

import pytest
from redteam_toolkit.modules import tls_audit
from tests.conftest import free_port


class TLSServer:
    """A local TLS server with a deliberately weak configuration."""

    def __init__(self, cert, key, min_version=None, max_version=None, ciphers: str | None = None):
        self.port = free_port()
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(cert), str(key))
        if min_version is not None:
            self.context.minimum_version = min_version
        if max_version is not None:
            self.context.maximum_version = max_version
        if ciphers:
            self.context.set_ciphers(ciphers)
        self._server = socket.socket()
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", self.port))
        self._server.listen(8)
        self._server.settimeout(0.3)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            try:
                with self.context.wrap_socket(conn, server_side=True) as tls:
                    tls.recv(1024)
                    tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            except (ssl.SSLError, OSError):
                pass

    def __enter__(self) -> TLSServer:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._server.close()
        self._thread.join(timeout=3)


@pytest.fixture(scope="module")
def tls_cert(tmp_path_factory):
    import subprocess

    directory = tmp_path_factory.mktemp("tlsmod")
    key = directory / "key.pem"
    cert = directory / "cert.pem"
    result = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key),
            "-out",
            str(cert),
            "-days",
            "2",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        capture_output=True,
        timeout=60,
        check=False,
    )
    if result.returncode != 0:
        pytest.skip("openssl is not usable here")
    return cert, key


@pytest.mark.network
class TestLiveAudit:
    def test_self_signed_certificate_is_flagged(self, tls_cert):
        """A bad chain is a finding, not a reason to abandon the audit."""
        with TLSServer(*tls_cert) as server:
            report = tls_audit.audit("127.0.0.1", server.port, sni="localhost", verify=True, timeout=5.0)

        assert report.data["connected"] is True
        assert report.data["verification"] == "self_signed"
        finding = next(f for f in report.findings if f.check == "tls.certificate-untrusted")
        assert finding.severity == "high"
        # The rest of the audit still ran.
        assert any(f.check.startswith("tls.protocol") for f in report.findings)

    def test_tls13_is_credited(self, tls_cert):
        with TLSServer(*tls_cert) as server:
            report = tls_audit.audit("127.0.0.1", server.port, sni="localhost", verify=False, timeout=5.0)
        assert report.data["version_label"] == "TLS 1.3"
        assert any(f.check == "tls.protocol" and f.severity == "info" for f in report.findings)

    def test_weak_cipher_is_flagged(self, tls_cert):
        """Pin TLS 1.2 so the server's weak CBC suite is actually negotiated."""
        with TLSServer(
            *tls_cert,
            min_version=ssl.TLSVersion.TLSv1_2,
            max_version=ssl.TLSVersion.TLSv1_2,
            ciphers="AES128-SHA:DES-CBC3-SHA",
        ) as server:
            report = tls_audit.audit("127.0.0.1", server.port, sni="localhost", verify=False, timeout=5.0)

        assert report.data["version_label"] == "TLS 1.2"
        assert any(f.check == "tls.cipher" for f in report.findings)
        assert any(f.check == "tls.legacy-block-cipher" for f in report.findings)

    def test_cipher_details_are_captured(self, tls_cert):
        with TLSServer(*tls_cert) as server:
            report = tls_audit.audit("127.0.0.1", server.port, sni="localhost", verify=False, timeout=5.0)
        assert report.data["cipher"]
        assert report.data["cipher_bits"] > 0
        assert report.data["certificate"]["sha256_fingerprint"]

    def test_ip_target_without_sni_still_audits(self, tls_cert):
        """A verifying context needs a server_hostname even for a bare IP."""
        with TLSServer(*tls_cert) as server:
            report = tls_audit.audit("127.0.0.1", server.port, sni=None, verify=True, timeout=5.0)
        assert report.data["connected"] is True
        assert not any(f.check == "tls.unreachable" for f in report.findings)

    def test_verification_skipped_is_stated_not_implied_clean(self, tls_cert):
        with TLSServer(*tls_cert) as server:
            report = tls_audit.audit("127.0.0.1", server.port, sni="localhost", verify=False, timeout=5.0)
        assert report.data["verification"] == "skipped"
        assert report.data["verification_performed"] is False


@pytest.mark.network
class TestUnreachable:
    def test_closed_port_is_reported_not_raised(self, closed_port: int):
        report = tls_audit.audit("127.0.0.1", closed_port, verify=False, timeout=1.0)
        assert report.data["connected"] is False
        assert any(f.check == "tls.unreachable" for f in report.findings)

    def test_plain_http_port_is_reported_not_raised(self, http_server):
        report = tls_audit.audit("127.0.0.1", http_server.port, verify=False, timeout=2.0)
        assert not report.data["connected"]
        assert any(f.check == "tls.unreachable" for f in report.findings)


class TestProtocolMatrix:
    def test_matrix_keys_use_consistent_labels(self):
        assert set(tls_audit.protocol_support_matrix("127.0.0.1", 1, timeout=0.3)) <= {
            "TLS 1.3",
            "TLS 1.2",
            "TLS 1.1",
            "TLS 1.0",
        }

    def test_offered_versions_reflects_what_this_openssl_allows(self):
        """A high security level disables TLS 1.0/1.1 client-side, which is not
        the same as the server refusing them."""
        offered = tls_audit.client_offered_versions()
        assert "TLS 1.2" in offered
        assert "TLS 1.3" in offered

    @pytest.mark.network
    def test_deprecated_protocols_are_detected(self, tls_cert):
        """Guarded, because most modern stacks cannot complete a TLS 1.0 handshake.

        A context may be constructible for TLS 1.0 and still have no usable
        cipher at the system security level, so the positive path is only
        meaningful when a real handshake succeeds.
        """
        with TLSServer(*tls_cert, min_version=ssl.TLSVersion.TLSv1) as server:
            matrix = tls_audit.protocol_support_matrix("127.0.0.1", server.port, timeout=3.0)
            if not any(matrix.get(label) for label in ("TLS 1.0", "TLS 1.1")):
                pytest.skip("this OpenSSL/cipher configuration cannot complete a TLS 1.x handshake")
        assert matrix["TLS 1.0"] is True
        assert matrix["TLS 1.1"] is True

    @pytest.mark.network
    def test_modern_only_server_rejects_old_protocols(self, tls_cert):
        with TLSServer(*tls_cert, min_version=ssl.TLSVersion.TLSv1_2) as server:
            matrix = tls_audit.protocol_support_matrix("127.0.0.1", server.port, timeout=3.0)
        assert matrix.get("TLS 1.0") is False
        assert matrix.get("TLS 1.1") is False
        assert matrix.get("TLS 1.2") is True


class TestHelpers:
    @pytest.mark.parametrize(
        "raw,label",
        [
            ("TLSv1.3", "TLS 1.3"),
            ("TLSv1.2", "TLS 1.2"),
            ("TLSv1.1", "TLS 1.1"),
            ("TLSv1", "TLS 1.0"),
            ("SSLv3", "SSL 3.0"),
            (None, "unknown"),
        ],
    )
    def test_version_labels(self, raw, label):
        assert tls_audit._version_label(raw) == label

    @pytest.mark.parametrize(
        "message,verdict",
        [
            ("certificate has expired", "expired"),
            ("certificate is not yet valid", "not_yet_valid"),
            ("self-signed certificate", "self_signed"),
            ("hostname mismatch, certificate is not valid", "hostname_mismatch"),
            ("unable to get local issuer certificate", "incomplete_chain"),
            ("unknown ca", "untrusted_ca"),
            ("something entirely new", "verification_failed"),
        ],
    )
    def test_verification_error_classification(self, message: str, verdict: str):
        assert tls_audit._classify_verify(message) == verdict

    def test_ip_literal_detection(self):
        assert tls_audit._is_ip_literal("127.0.0.1")
        assert tls_audit._is_ip_literal("::1")
        assert not tls_audit._is_ip_literal("example.com")

    def test_certificate_date_parsing(self):
        parsed = tls_audit._parse_cert_date("Mar  4 10:00:00 2027 GMT")
        assert parsed is not None
        assert parsed.year == 2027
        assert tls_audit._parse_cert_date("nonsense") is None
        assert tls_audit._parse_cert_date(None) is None

    def test_cipher_check_flags_a_non_aead_suite(self):
        from redteam_toolkit.models import Report

        report = Report(module="tls_audit", target="t")
        tls_audit._check_cipher(report, {"cipher": "AES128-SHA", "cipher_bits": 128})
        finding = next(f for f in report.findings if f.check == "tls.cipher")
        assert "AEAD" in finding.detail

    def test_cipher_check_credits_an_aead_suite(self):
        from redteam_toolkit.models import Report

        report = Report(module="tls_audit", target="t")
        tls_audit._check_cipher(report, {"cipher": "TLS_AES_256_GCM_SHA384", "cipher_bits": 256})
        assert [f.check for f in report.findings] == ["tls.cipher-strict"]

    def test_deprecated_protocol_verdicts(self):
        from redteam_toolkit.models import Report

        for label, check in (
            ("SSL 3.0", "tls.protocol"),
            ("TLS 1.0", "tls.protocol"),
            ("TLS 1.2", "tls.protocol"),
            ("TLS 1.3", "tls.protocol"),
        ):
            report = Report(module="tls_audit", target="t")
            tls_audit._check_version(report, {"version_label": label})
            assert [f.check for f in report.findings] == [check], label
