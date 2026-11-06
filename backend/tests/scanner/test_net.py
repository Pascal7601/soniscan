"""The network layer against REAL servers on loopback, using real OpenSSL certificates.

No mocking of sockets or TLS: these tests prove the certificate classification, IP pinning, legacy
protocol detection and timeout behaviour of scanner/net.py. They need the `openssl` command line
tool (present on standard CI images) and skip without it.
"""

import contextlib
import shutil
import socket
import ssl
import subprocess
import threading
from datetime import UTC, datetime, timedelta

import pytest

from scanner import net
from scanner.net import (
    StdlibTlsProbe,
    StdlibWebClient,
    TlsProbeError,
    classify_certificate_error,
)
from scanner.safety import UnsafeTarget

pytestmark = [
    pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl command not available"),
    pytest.mark.filterwarnings("ignore::DeprecationWarning"),  # TLS 1.0/1.1 constants are deprecated
]

LOOPBACK = lambda host: ["127.0.0.1"]  # noqa: E731
OK = (
    b"HTTP/1.1 200 OK\r\nStrict-Transport-Security: max-age=31536000\r\n"
    b"Server: nginx/1.18.0\r\nVary: Accept\r\nVary: Cookie\r\nContent-Length: 0\r\n"
    b"Connection: close\r\n\r\n"
)


# ---- a small real PKI --------------------------------------------------------------------------

OPENSSL = shutil.which("openssl")


def _openssl(*args, cwd):
    subprocess.run([OPENSSL, *args], cwd=cwd, check=True, capture_output=True)  # noqa: S603


@pytest.fixture(scope="module")
def pki(tmp_path_factory):
    d = tmp_path_factory.mktemp("pki")

    def ca(name):
        _openssl(
            "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
            "-out", f"{name}.pem", "-days", "30", "-subj", f"/CN={name}",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            cwd=d,
        )  # fmt: skip

    def leaf(name, san, days, issuer):
        _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", f"{name}.key",
                 "-out", f"{name}.csr", "-subj", f"/CN={san}", cwd=d)  # fmt: skip
        (d / f"{name}.ext").write_text(f"subjectAltName=DNS:{san}\nbasicConstraints=CA:FALSE\n")
        _openssl("x509", "-req", "-in", f"{name}.csr", "-CA", f"{issuer}.pem", "-CAkey",
                 f"{issuer}.key", "-CAcreateserial", "-out", f"{name}.pem", "-days", str(days),
                 "-extfile", f"{name}.ext", cwd=d)  # fmt: skip

    ca("ca")
    ca("otherca")
    leaf("good", "localhost", 10, "ca")
    leaf("mismatch", "other.example", 10, "ca")
    leaf("untrusted", "localhost", 10, "otherca")
    _openssl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "selfsigned.key",
             "-out", "selfsigned.pem", "-days", "10", "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost", cwd=d)  # fmt: skip

    # A genuinely expired certificate: `openssl ca` can set exact validity dates.
    (d / "cadb").mkdir()
    (d / "cadb" / "index.txt").write_text("")
    (d / "cadb" / "serial").write_text("01\n")
    (d / "ca.cnf").write_text(
        "[ca]\ndefault_ca = CA_default\n[CA_default]\ndatabase = cadb/index.txt\n"
        "new_certs_dir = cadb\nserial = cadb/serial\ndefault_md = sha256\npolicy = policy_any\n"
        "unique_subject = no\ncopy_extensions = copy\n[policy_any]\ncommonName = supplied\n"
    )
    _openssl("req", "-newkey", "rsa:2048", "-nodes", "-keyout", "expired.key", "-out",
             "expired.csr", "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
             cwd=d)  # fmt: skip
    _openssl("ca", "-batch", "-config", "ca.cnf", "-cert", "ca.pem", "-keyfile", "ca.key", "-in",
             "expired.csr", "-out", "expired.pem", "-startdate", "20200101000000Z", "-enddate",
             "20200102000000Z", "-notext", cwd=d)  # fmt: skip
    return d


@pytest.fixture
def trusted(pki, monkeypatch):
    """Make the test CA the only trusted authority for default TLS contexts."""
    monkeypatch.setenv("SSL_CERT_FILE", str(pki / "ca.pem"))
    monkeypatch.setenv("SSL_CERT_DIR", str(pki))


class Server:
    """A real listening socket on loopback, optionally speaking TLS. Records raw requests."""

    def __init__(self, pki=None, cert=None, *, response=OK, versions=None, hang=False):
        self._context = None
        if cert:
            self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self._context.load_cert_chain(pki / f"{cert}.pem", pki / f"{cert}.key")
            if versions:
                self._context.minimum_version, self._context.maximum_version = versions
                self._context.set_ciphers("ALL:@SECLEVEL=0")
        self._response, self._hang = response, hang
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self._sock.settimeout(0.2)
        self.port = self._sock.getsockname()[1]
        self.requests: list[bytes] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join(2)
        self._sock.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            if self._context:
                conn = self._context.wrap_socket(conn, server_side=True)
            if self._hang:
                self._stop.wait(3)
                return
            data = conn.recv(8192)
            if data:
                self.requests.append(data)
                conn.sendall(self._response)
        except (ssl.SSLError, OSError):
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()


def probe_for(server, **kwargs):
    return StdlibTlsProbe(port=server.port, resolve=LOOPBACK, timeout=3, **kwargs)


def client_for(server, **kwargs):
    return StdlibWebClient(resolve=LOOPBACK, allowed_ports=(server.port,), timeout=3, **kwargs)


# ---- TLS probe: real handshakes ----------------------------------------------------------------


def test_a_trusted_certificate_is_read_correctly(pki, trusted):
    with Server(pki, "good") as server:
        observed = probe_for(server).probe("localhost")

    assert (observed.resolved, observed.reachable, observed.cert_problem) == (True, True, None)
    assert observed.protocol == "TLSv1.3"
    days_left = (observed.not_after - datetime.now(UTC)) / timedelta(days=1)
    assert 9 < days_left < 10.1  # the certificate was issued for 10 days
    assert observed.legacy_protocols == ()
    assert observed.modern_tls is True


@pytest.mark.parametrize(
    ("cert", "problem"),
    [
        ("mismatch", "hostname_mismatch"),
        ("untrusted", "untrusted_chain"),
        ("selfsigned", "self_signed"),
        ("expired", "expired"),
    ],
)
def test_real_certificate_problems_are_classified(pki, trusted, cert, problem):
    with Server(pki, cert) as server:
        observed = probe_for(server).probe("localhost")
    assert observed.cert_problem == problem
    assert observed.not_after is None  # not judged when the chain is not trusted


def test_a_closed_port_means_not_reachable():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
    observed = StdlibTlsProbe(port=free_port, resolve=LOOPBACK).probe("localhost")
    assert (observed.resolved, observed.reachable) == (True, False)


def test_internal_addresses_are_refused_by_the_safety_guard(pki):
    """No resolver injected: 'localhost' resolves to loopback, which must never be probed."""
    with Server(pki, "good") as server:
        observed = StdlibTlsProbe(port=server.port, timeout=3).probe("localhost")
        assert server.requests == []
    assert observed.resolved is False


def test_a_resolver_that_refuses_means_no_web_presence():
    def refuse(host):
        raise UnsafeTarget("no public address")

    observed = StdlibTlsProbe(resolve=refuse).probe("nothing.example")
    assert (observed.resolved, observed.reachable) == (False, False)


def test_the_host_is_resolved_once_and_the_approved_address_is_reused(pki, trusted):
    calls = []

    def resolve(host):
        calls.append(host)
        return ["127.0.0.1"]

    with Server(pki, "good") as server:
        StdlibTlsProbe(port=server.port, resolve=resolve, timeout=3).probe("localhost")
    assert calls == ["localhost"]  # not once per handshake: no window for DNS to change


def test_a_server_that_does_not_speak_tls_fails_the_probe_instead_of_being_guessed_about():
    with Server(response=b"HTTP/1.1 200 OK\r\n\r\n") as server, pytest.raises(TlsProbeError):
        probe_for(server).probe("localhost")


# ---- TLS probe: legacy protocols ---------------------------------------------------------------

TLS10, TLS11 = ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1_1
TLS12, TLS13 = ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3


def _skip_if_legacy_unsupported(pki):
    try:
        with Server(pki, "good", versions=(TLS10, TLS13)) as server:
            if not net._accepts_legacy("127.0.0.1", server.port, "localhost", TLS10, 3):
                pytest.skip("this OpenSSL build cannot speak TLS 1.0")
    except ValueError:
        pytest.skip("this OpenSSL build cannot speak TLS 1.0")


def test_a_server_accepting_old_protocols_alongside_new_ones_is_detected(pki, trusted):
    _skip_if_legacy_unsupported(pki)
    with Server(pki, "good", versions=(TLS10, TLS13)) as server:
        observed = probe_for(server).probe("localhost")
    assert observed.legacy_protocols == ("TLSv1", "TLSv1.1")
    assert observed.modern_tls is True
    assert observed.protocol == "TLSv1.3"


def test_a_server_that_only_speaks_old_protocols_is_reported_not_lost(pki, trusted):
    """Regression: the modern handshake fails outright; that must not hide the worst case."""
    _skip_if_legacy_unsupported(pki)
    with Server(pki, "good", versions=(TLS10, TLS11)) as server:
        observed = probe_for(server).probe("localhost")
    assert observed.modern_tls is False
    assert observed.legacy_protocols == ("TLSv1", "TLSv1.1")


def test_a_modern_only_server_has_no_legacy_protocols(pki, trusted):
    with Server(pki, "good", versions=(TLS12, TLS13)) as server:
        assert probe_for(server).probe("localhost").legacy_protocols == ()


def test_legacy_probing_can_be_switched_off(pki, trusted):
    _skip_if_legacy_unsupported(pki)
    with Server(pki, "good", versions=(TLS10, TLS13)) as server:
        assert probe_for(server, probe_legacy=False).probe("localhost").legacy_protocols == ()


# ---- certificate error classification ----------------------------------------------------------


def _verify_error(code, message="x"):
    exc = ssl.SSLCertVerificationError(1, message)
    exc.verify_code, exc.verify_message = code, message
    return exc


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (10, "expired"),
        (18, "self_signed"),
        (62, "hostname_mismatch"),
        (19, "untrusted_chain"),
        (20, "untrusted_chain"),
        (21, "untrusted_chain"),
        (2, "untrusted_chain"),
    ],
)
def test_verification_codes_map_to_problems(code, expected):
    assert classify_certificate_error(_verify_error(code)) == expected


@pytest.mark.parametrize("code", [9, 23, 99])
def test_unknown_verification_codes_fail_loudly_instead_of_being_guessed(code):
    with pytest.raises(TlsProbeError, match="unclassified"):
        classify_certificate_error(_verify_error(code, "certificate is not yet valid"))


# ---- web client --------------------------------------------------------------------------------


def test_https_headers_are_lowercased_and_repeats_are_joined(pki):
    with Server(pki, "good") as server:
        response = client_for(server).get(f"https://localhost:{server.port}/")
    assert response.status == 200
    assert response.headers["strict-transport-security"] == "max-age=31536000"
    assert response.headers["server"] == "nginx/1.18.0"
    assert response.headers["vary"] == "Accept, Cookie"


def test_headers_are_read_even_when_the_certificate_is_bad(pki):
    with Server(pki, "selfsigned") as server:
        assert client_for(server).get(f"https://localhost:{server.port}/").status == 200


def test_plain_http_works(pki):
    with Server() as server:
        response = client_for(server).get(f"http://localhost:{server.port}/")
    assert response.status == 200


def test_redirects_are_returned_not_followed(pki):
    redirect = (
        b"HTTP/1.1 302 Found\r\nLocation: https://elsewhere.example/\r\nConnection: close\r\n\r\n"
    )
    with Server(pki, "good", response=redirect) as server:
        response = client_for(server).get(f"https://localhost:{server.port}/")
        assert len(server.requests) == 1
    assert response.status == 302
    assert response.headers["location"] == "https://elsewhere.example/"


def test_the_request_identifies_the_scanner_and_carries_the_path(pki):
    with Server(pki, "good") as server:
        client_for(server).get(f"https://localhost:{server.port}/a/b?x=1")
        request = server.requests[0]
    assert request.startswith(b"GET /a/b?x=1 HTTP/1.1\r\n")
    assert b"User-Agent: PostureScanner/" in request
    assert b"Connection: close" in request


def test_the_connection_goes_to_the_approved_address_not_to_a_fresh_lookup(pki):
    """'pinned.example' does not resolve anywhere: only the injected address can be reached."""
    with Server(pki, "good") as server:
        response = client_for(server).get(f"https://pinned.example:{server.port}/")
        assert f"Host: pinned.example:{server.port}".encode() in server.requests[0]
    assert response.status == 200


def test_a_refused_connection_means_nothing_to_talk_to():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        free_port = sock.getsockname()[1]
    client = StdlibWebClient(resolve=LOOPBACK, allowed_ports=(free_port,))
    assert client.get(f"http://localhost:{free_port}/") is None


def test_the_web_client_also_refuses_internal_addresses(pki):
    with Server() as server:
        client = StdlibWebClient(allowed_ports=(server.port,))  # real resolve_public
        assert client.get(f"http://localhost:{server.port}/") is None
        assert server.requests == []


@pytest.mark.parametrize(
    "url",
    [
        "ftp://acme.example/",
        "http:///nohost",
        "https://acme.example:8443/",
        "http://acme.example:8080/",
    ],
)
def test_unsupported_schemes_and_ports_are_refused(url):
    with pytest.raises(ValueError, match=r"unsupported URL|not allowed"):
        StdlibWebClient(resolve=LOOPBACK).get(url)


def test_a_server_that_never_answers_raises_a_timeout(pki):
    with Server(pki, "good", hang=True) as server:
        client = StdlibWebClient(resolve=LOOPBACK, allowed_ports=(server.port,), timeout=0.5)
        with pytest.raises(TimeoutError):
            client.get(f"https://localhost:{server.port}/")