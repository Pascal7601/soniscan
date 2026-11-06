"""Real network access for checks: a TLS probe and a plain web client.

Every connection made here follows the same rules, which exist to keep the scanner from being
turned against anything it should not touch:

  1. The host is resolved through `safety.resolve_public`; private and internal addresses are
     refused, so the scanner cannot be aimed at internal infrastructure (SSRF).
  2. We connect to the IP address that guard approved, never to the host name again, so DNS
     cannot change between the check and the connection (DNS rebinding). The host name is still
     used for the TLS server name and the HTTP Host header.
  3. Only ports 80 and 443 (tests may allow others).
  4. Every operation has a timeout.
  5. We identify ourselves with a User-Agent.

"Nothing to talk to" (no public address, connection refused) is a normal answer. Timeouts and
anything unexpected RAISE, so a check fails instead of guessing.
"""

import http.client
import socket
import ssl
import urllib.parse
from collections.abc import Callable
from datetime import UTC, datetime

from . import __version__
from .safety import UnsafeTarget, resolve_public
from .types import TlsObservation, WebResponse

Resolve = Callable[[str], list[str]]

DEFAULT_USER_AGENT = f"PostureScanner/{__version__}"

# OpenSSL X509 verification error codes (X509_V_ERR_*) mapped to the problems we report.
_EXPIRED = {10}
_SELF_SIGNED = {18}  # the server's own certificate is self-signed
_UNTRUSTED_CHAIN = {2, 19, 20, 21}  # unknown issuer, private CA, or an incomplete chain
_HOSTNAME_MISMATCH = {62}

# Handshake failures that mean "we spoke TLS 1.2 or newer and the server could not".
_VERSION_MISMATCH_REASONS = {
    "TLSV1_ALERT_PROTOCOL_VERSION",
    "UNSUPPORTED_PROTOCOL",
    "WRONG_VERSION_NUMBER",
}

_LEGACY_PROTOCOLS = (("TLSv1", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1))


class TlsProbeError(Exception):
    """The probe could not tell what is wrong (an unclassified failure); the check must fail."""


def classify_certificate_error(exc: ssl.SSLCertVerificationError) -> str:
    code = exc.verify_code
    if code in _EXPIRED:
        return "expired"
    if code in _SELF_SIGNED:
        return "self_signed"
    if code in _HOSTNAME_MISMATCH:
        return "hostname_mismatch"
    if code in _UNTRUSTED_CHAIN:
        return "untrusted_chain"
    raise TlsProbeError(f"unclassified certificate error {code}: {exc.verify_message}")


def _pick(addresses: list[str]) -> str:
    """Prefer an IPv4 address; fall back to the first address."""
    return next((a for a in addresses if ":" not in a), addresses[0])


def _not_after(certificate: dict) -> datetime | None:
    raw = certificate.get("notAfter") if certificate else None
    return datetime.fromtimestamp(ssl.cert_time_to_seconds(raw), UTC) if raw else None


def _accepts_legacy(ip: str, port: int, host: str, version: ssl.TLSVersion, timeout: float) -> bool:
    """Does the server complete a handshake using only this old protocol version?

    Certificate checks are off on purpose: this asks about the protocol, not the certificate. Any
    failure counts as "not accepted", which is conservative: a client library that cannot speak
    this version at all can never produce a false finding.
    """
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = context.maximum_version = version
        context.set_ciphers("ALL:@SECLEVEL=0")
        with (
            socket.create_connection((ip, port), timeout) as raw,
            context.wrap_socket(raw, server_hostname=host),
        ):
            return True
    except (ssl.SSLError, OSError, ValueError):
        return False


class StdlibTlsProbe:
    def __init__(
        self,
        *,
        timeout: float = 5.0,
        port: int = 443,
        resolve: Resolve = resolve_public,
        probe_legacy: bool = True,
    ) -> None:
        self._timeout, self._port, self._resolve = timeout, port, resolve
        self._probe_legacy = probe_legacy

    def probe(self, host: str) -> TlsObservation:
        try:
            ip = _pick(self._resolve(host))
        except UnsafeTarget:
            return TlsObservation(resolved=False, reachable=False)  # no web presence to judge

        context = ssl.create_default_context()  # verifies the chain, expiry and host name
        try:
            raw = socket.create_connection((ip, self._port), self._timeout)
        except ConnectionRefusedError:
            return TlsObservation(reachable=False)

        try:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                protocol = tls.version()
                not_after = _not_after(tls.getpeercert() or {})
        except ssl.SSLCertVerificationError as exc:
            return TlsObservation(
                cert_problem=classify_certificate_error(exc),
                legacy_protocols=self._legacy(ip, host),
            )
        except ssl.SSLError as exc:
            if (exc.reason or "") in _VERSION_MISMATCH_REASONS:
                # A server that only speaks old TLS is the worst case, and must be reported, not
                # lost as an error. If it will not talk any old version either, we cannot tell.
                legacy = self._legacy(ip, host)
                if legacy:
                    return TlsObservation(modern_tls=False, legacy_protocols=legacy)
            raise TlsProbeError(f"TLS handshake failed: {exc.reason or exc}") from exc
        finally:
            raw.close()

        return TlsObservation(
            protocol=protocol, not_after=not_after, legacy_protocols=self._legacy(ip, host)
        )

    def _legacy(self, ip: str, host: str) -> tuple[str, ...]:
        if not self._probe_legacy:
            return ()
        return tuple(
            name
            for name, version in _LEGACY_PROTOCOLS
            if _accepts_legacy(ip, self._port, host, version, self._timeout)
        )


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """Connects to a fixed, already-approved IP address instead of resolving the host again."""

    def __init__(self, host: str, ip: str, port: int, timeout: float) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip = ip

    def connect(self) -> None:
        self.sock = socket.create_connection((self._ip, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self, host: str, ip: str, port: int, timeout: float, context: ssl.SSLContext
    ) -> None:
        super().__init__(host, port, timeout=timeout)
        self._ip, self._tls_context = ip, context

    def connect(self) -> None:
        raw = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._tls_context.wrap_socket(raw, server_hostname=self.host)


class StdlibWebClient:
    """One GET at a time; never follows redirects (the caller decides, and re-checks safety)."""

    def __init__(
        self,
        *,
        timeout: float = 5.0,
        user_agent: str = DEFAULT_USER_AGENT,
        resolve: Resolve = resolve_public,
        allowed_ports: tuple[int, ...] = (80, 443),
    ) -> None:
        self._timeout, self._user_agent, self._resolve = timeout, user_agent, resolve
        self._allowed_ports = allowed_ports
        # Headers are judged whatever the certificate looks like; the TLS check reports bad
        # certificates separately, and we send nothing secret.
        self._context = ssl.create_default_context()
        self._context.check_hostname = False
        self._context.verify_mode = ssl.CERT_NONE

    def get(self, url: str) -> WebResponse | None:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise ValueError(f"unsupported URL: {url!r}")
        https = parts.scheme == "https"
        port = parts.port or (443 if https else 80)
        if port not in self._allowed_ports:
            raise ValueError(f"port {port} is not allowed")
        host = parts.hostname

        try:
            ip = _pick(self._resolve(host))
        except UnsafeTarget:
            return None

        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        connection: http.client.HTTPConnection = (
            _PinnedHTTPSConnection(host, ip, port, self._timeout, self._context)
            if https
            else _PinnedHTTPConnection(host, ip, port, self._timeout)
        )
        try:
            connection.request(
                "GET",
                path,
                headers={
                    "User-Agent": self._user_agent,
                    "Accept": "text/html,*/*;q=0.8",
                    "Connection": "close",
                },
            )
            response = connection.getresponse()  # the body is never read
            headers: dict[str, str] = {}
            for name, value in response.getheaders():
                key = name.lower()
                headers[key] = f"{headers[key]}, {value}" if key in headers else value
            return WebResponse(status=response.status, headers=headers, url=url)
        except ConnectionRefusedError:
            return None
        finally:
            connection.close()