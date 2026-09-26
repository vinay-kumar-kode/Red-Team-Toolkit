"""HTTP configuration scanning against a real local HTTP server."""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from redteam_toolkit.modules import webscan
from tests.conftest import free_port

#: A deliberately badly configured response: no protective headers, a leaky
#: banner, a cookie with no attributes, TRACE enabled, and /.env served.
LEAKY_HEADERS = {
    "Server": "Apache/2.4.29 (Ubuntu)",
    "X-Powered-By": "PHP/7.2.24",
    "Set-Cookie": "PHPSESSID=abc123; path=/",
    "Content-Security-Policy": "default-src * 'unsafe-inline' 'unsafe-eval'",
    "Allow": "GET, POST, PUT, DELETE",
    "X-Frame-Options": "DENY",
    "Content-Type": "text/html; charset=utf-8",
}

SECURE_HEADERS = {
    "Server": "nginx",
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "default-src 'self'; script-src 'nonce-abc123'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Set-Cookie": "sid=x; Secure; HttpOnly; SameSite=Strict",
    "Permissions-Policy": "geolocation=(), camera=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Type": "text/html; charset=utf-8",
}


def make_handler(
    headers: dict[str, str],
    status: int,
    body: str,
    trace: bool,
    serve_env: bool,
    strict: bool,
    query_echo: bool = False,
):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def log_message(self, *args):
            return

        def _respond(self, code: int, payload: bytes) -> None:
            self.send_response(code)
            for key, value in headers.items():
                if key.lower() == "content-length":
                    continue
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            if self.path == "/.env" and serve_env:
                self._respond(200, b"DB_PASSWORD=hunter2\n")
                return
            if self.path == "/.git/config":
                # One path that is genuinely absent, so a test can prove a 404 is
                # not reported as an exposure.
                self._respond(404, b"not found")
                return
            # A real server 404s unknown paths. Without this the "secure" fixture
            # would answer 200 to every path the scanner probes, which is a
            # different (and much noisier) test.
            if query_echo and self.path.startswith("/?"):
                self._respond(200, f"<html>You searched: {self.path.split('q=')[-1]}</html>".encode())
                return
            if self.path != "/" and strict:
                self._respond(404, b"not found")
                return
            self._respond(status, body.encode())

        def do_OPTIONS(self):
            self.send_response(200)
            self.send_header("Allow", "GET, POST, PUT, DELETE")
            self.send_header("Content-Length", "0")
            self.end_headers()

        if trace:

            def do_TRACE(self):  # noqa: N802
                self._respond(200, self.requestline.encode())

    return Handler


class LocalServer:
    def __init__(
        self,
        headers,
        status=200,
        body="<html><body>hi</body></html>",
        trace=True,
        serve_env=True,
        strict=False,
        query_echo=False,
    ):
        self.port = free_port()
        handler = make_handler(headers, status, body, trace, serve_env, strict, query_echo)
        self._server = ThreadingHTTPServer(("127.0.0.1", self.port), handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=3)

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"


@pytest.fixture
def leaky():
    with LocalServer(LEAKY_HEADERS) as server:
        yield server


@pytest.fixture
def secure():
    with LocalServer(SECURE_HEADERS, trace=False, serve_env=False, strict=True) as server:
        yield server


@pytest.mark.network
class TestLeaks:
    def test_missing_security_headers_are_reported(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False, check_methods=False)
        missing = set(report.data["headers_missing"])
        assert "Content-Security-Policy" not in missing
        assert "Strict-Transport-Security" in missing
        assert any(f.check == "web.header-missing" for f in report.findings)

    def test_technology_disclosure_is_reported(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False, check_methods=False)
        checks = {f.check for f in report.findings}
        assert "web.header-disclosure" in checks
        assert "web.version-disclosure" in checks
        products = {d["product"] for d in report.data["software_detected"]}
        assert "Apache HTTP Server" in products

    def test_cookie_attributes_are_reported(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False, check_methods=False)
        finding = next(f for f in report.findings if f.check == "web.cookie-attributes")
        assert set(finding.evidence["missing"]) == {"Secure", "HttpOnly", "SameSite"}

    def test_weak_csp_is_reported(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False, check_methods=False)
        finding = next(f for f in report.findings if f.check == "web.csp-weak")
        assert "default-src" in finding.detail

    def test_plain_http_is_reported(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False, check_methods=False)
        assert any(f.check == "web.no-https" for f in report.findings)

    def test_exposed_env_file_is_critical(self, leaky):
        report = webscan.scan(leaky.url, check_methods=False)
        finding = next(f for f in report.findings if f.check == "web.exposed-path")
        assert finding.severity == "critical"
        assert "/.env" in report.data["exposed_paths"]

    def test_404_paths_are_not_reported_as_exposed(self, leaky):
        report = webscan.scan(leaky.url, check_methods=False)
        assert "/.git/config" not in report.data["exposed_paths"]

    def test_trace_is_reported(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False)
        assert any(f.check == "web.trace-enabled" for f in report.findings)

    def test_write_methods_are_reported(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False)
        assert any(f.check == "web.write-methods" for f in report.findings)


@pytest.mark.network
class TestCleanTarget:
    def test_well_configured_server_has_only_the_http_scheme_finding(self, secure):
        """Plain HTTP is the sole high finding, and it is a property of the fixture.

        A local test server cannot speak TLS without extra machinery, so this
        asserts that nothing *else* is wrong, rather than pretending HTTP is fine.
        """
        report = webscan.scan(secure.url)
        assert not report.at_or_above("critical")
        high = {f.check for f in report.at_or_above("high")}
        assert high <= {"web.no-https"}, high

    def test_present_headers_are_credited(self, secure):
        report = webscan.scan(secure.url, check_paths=False, check_methods=False)
        assert not report.data["headers_missing"]
        assert "Strict-Transport-Security" in report.data["headers_present"]

    def test_strict_csp_is_credited(self, secure):
        report = webscan.scan(secure.url, check_paths=False, check_methods=False)
        assert any(f.check == "web.csp-strict" for f in report.findings)

    def test_no_leak_finding_when_version_header_is_generic(self, secure):
        report = webscan.scan(secure.url, check_paths=False, check_methods=False)
        assert not any(f.check == "web.version-disclosure" for f in report.findings)


class TestCspParsing:
    def test_default_src_is_used_as_the_script_src_fallback(self):
        directives = webscan._parse_csp("default-src * 'unsafe-inline'")
        assert directives["default-src"] == "* 'unsafe-inline'"
        assert "script-src" not in directives

    def test_directive_values_are_split_on_semicolons(self):
        directives = webscan._parse_csp("default-src 'self'; script-src 'self' https://cdn.example")
        assert directives["script-src"] == "'self' https://cdn.example"

    @pytest.mark.parametrize(
        "policy,weak",
        [
            ("script-src *", True),
            ("script-src 'unsafe-inline'", True),
            ("script-src 'unsafe-eval'", True),
            ("script-src data:", True),
            ("default-src *", True),
            ("script-src 'none'", False),
            ("script-src 'self'", False),
            ("script-src 'nonce-abc'", False),
            ("default-src 'self'; script-src 'strict-dynamic' 'nonce-abc'", False),
        ],
    )
    def test_policy_strength_classification(self, policy: str, weak: bool):
        from redteam_toolkit.models import Report

        report = Report(module="webscan", target="t")

        class FakeResponse:
            headers = {"Content-Security-Policy": policy}

        webscan._check_csp(FakeResponse(), report)  # type: ignore[arg-type]
        checks = {f.check for f in report.findings}
        if weak:
            assert checks == {"web.csp-weak"}
        else:
            assert checks == {"web.csp-strict"}


class TestCookieParsing:
    def test_attributes_are_read_case_insensitively(self):
        from redteam_toolkit.models import Report

        report = Report(module="webscan", target="t")

        class FakeRaw:
            def __init__(self):
                self.headers = type(
                    "H",
                    (),
                    {"get_all": staticmethod(lambda name: ["SID=abc; secure; httponly; samesite=lax"])},
                )()

        class FakeResponse:
            raw = FakeRaw()
            headers = {}

        webscan._check_cookies(FakeResponse(), report)  # type: ignore[arg-type]
        assert [f.check for f in report.findings] == ["web.cookie-attributes-ok"]

    def test_missing_attributes_are_listed(self):
        from redteam_toolkit.models import Report

        report = Report(module="webscan", target="t")

        class FakeRaw:
            def __init__(self):
                self.headers = type("H", (), {"get_all": staticmethod(lambda n: ["SID=abc; path=/"])})()

        class FakeResponse:
            raw = FakeRaw()
            headers = {}

        webscan._check_cookies(FakeResponse(), report)  # type: ignore[arg-type]
        finding = report.findings[0]
        assert set(finding.evidence["missing"]) == {"Secure", "HttpOnly", "SameSite"}


class TestUrlHandling:
    def test_scheme_is_inferred_from_a_bare_host(self):
        assert webscan.scan("127.0.0.1:1/", check_paths=False).target.startswith("http://")
        assert webscan.scan("127.0.0.1:443/", check_paths=False).target.startswith("https://")

    def test_explicit_scheme_is_respected(self):
        assert webscan.scan("https://127.0.0.1:1/", check_paths=False).target == "https://127.0.0.1:1/"

    def test_unreachable_target_is_reported_not_raised(self, closed_port: int):
        report = webscan.scan(f"http://127.0.0.1:{closed_port}/", check_paths=False, check_methods=False)
        assert report.data["reachable"] is False
        assert any(f.check == "web.unreachable" for f in report.findings)

    def test_unreachable_target_produces_no_high_findings(self, closed_port: int):
        """An unreachable target is not a security finding, it is an operational one."""
        report = webscan.scan(f"http://127.0.0.1:{closed_port}/", check_paths=False, check_methods=False)
        assert not report.at_or_above("high")


@pytest.mark.network
class TestReflectionCheck:
    def test_reflection_is_opt_in(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False, check_methods=False)
        assert "reflection" not in report.data

    def test_non_reflection_is_reported_cleanly(self, leaky):
        report = webscan.scan(leaky.url, check_paths=False, check_methods=False, reflect_check=True)
        assert report.data["reflection"]["marker_occurrences"] == 0
        assert any(f.check == "web.no-reflection" for f in report.findings)

    def test_reflected_marker_is_flagged_for_manual_review(self):
        with LocalServer(
            SECURE_HEADERS,
            body="<html>You searched: rttmarker9x2q</html>",
            trace=False,
            serve_env=False,
            strict=True,
            query_echo=True,
        ) as server:
            report = webscan.scan(server.url, check_paths=False, check_methods=False, reflect_check=True)
        assert report.data["reflection"]["marker_occurrences"] == 1
        finding = next(f for f in report.findings if f.check == "web.reflected-input")
        assert "manual" in finding.detail.lower()
