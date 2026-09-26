"""Shared fixtures.

The tests never touch the network beyond loopback. Anything that needs a live
service starts one in-process on an ephemeral port, so the suite is hermetic
and does not depend on docker, root, or a reachable lab.
"""

from __future__ import annotations

import socket
import subprocess
import threading
from pathlib import Path

import pytest
from redteam_toolkit.utils import console as console_module

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _quiet_console():
    """Keep test output readable and colour decisions deterministic."""
    console_module.set_color(False)
    console_module.set_quiet(False)
    yield
    console_module.set_color(None)
    console_module.set_quiet(False)


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return REPO_ROOT


@pytest.fixture(scope="session")
def lab_files() -> Path:
    return REPO_ROOT / "lab"


def free_port() -> int:
    """An ephemeral port that is free right now."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ThreadedServer:
    """A tiny TCP server that answers with a fixed reply.

    Used instead of a real HTTP server where the test only needs "something is
    listening and it sends these bytes".
    """

    def __init__(self, reply: bytes = b"", delay: float = 0.0, read_first: bool = False) -> None:
        self.reply = reply
        self.delay = delay
        self.read_first = read_first
        self.port = free_port()
        self.received: list[bytes] = []
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/"

    def __enter__(self) -> ThreadedServer:
        self._server = socket.socket()
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", self.port))
        self._server.listen(16)
        self._server.settimeout(0.25)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        if self._server is not None:
            self._server.close()
        if self._thread is not None:
            self._thread.join(timeout=3)

    def _serve(self) -> None:
        assert self._server is not None
        while not self._stop.is_set():
            try:
                conn, _addr = self._server.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(2.0)
            try:
                if self.read_first:
                    data = conn.recv(4096)
                    self.received.append(data)
                if self.delay:
                    self._stop.wait(self.delay)
                if self.reply:
                    conn.sendall(self.reply)
            except OSError:
                pass


HTTP_RESPONSE = (
    b"HTTP/1.1 200 OK\r\n"
    b"Content-Type: text/html\r\n"
    b"Content-Length: 34\r\n"
    b"Connection: close\r\n"
    b"\r\n"
    b"<html><body>hello world body</body></html>"
)


@pytest.fixture
def http_server():
    with ThreadedServer(HTTP_RESPONSE, read_first=True) as server:
        yield server


@pytest.fixture
def banner_server():
    reply = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"
    with ThreadedServer(reply) as server:
        yield server


@pytest.fixture(scope="session")
def self_signed_cert(tmp_path_factory: pytest.TempPathFactory) -> tuple[Path, Path]:
    """A throwaway self-signed certificate, generated once per session.

    The stdlib cannot issue certificates, so this shells out to ``openssl``.
    Tests that use it are skipped when openssl is absent rather than failing,
    which keeps the suite runnable in a minimal container.
    """
    directory = tmp_path_factory.mktemp("tls")
    key_path = directory / "key.pem"
    cert_path = directory / "cert.pem"

    try:
        result = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(key_path),
                "-out",
                str(cert_path),
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
    except (OSError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"openssl is not usable here: {exc}")

    if result.returncode != 0 or not cert_path.is_file():
        pytest.skip(f"openssl could not issue a certificate: {result.stderr.decode()[:200]}")

    return key_path, cert_path


@pytest.fixture(scope="session")
def closed_port() -> int:
    """A port with nothing listening, so a connect is actively refused."""
    return free_port()
