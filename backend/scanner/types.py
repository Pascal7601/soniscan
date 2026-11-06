"""Plain data types shared by all checks. No framework imports allowed in this package."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol
from collections.abc import Mapping
from datetime import datetime


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class CheckResult:
    check_key: str  # stable id, matches a row in the check library
    severity: Severity
    exploitability: float  # 0..1, see the scoring model in the design document
    asset: str  # what it applies to, e.g. 'example.com'
    evidence: dict[str, object] = field(default_factory=dict)


class Resolver(Protocol):
    def txt(self, name: str) -> list[str]: ...


class CapabilityMissing(Exception):
    """A check needs a capability (TLS probe, web client) that the caller did not provide."""


@dataclass(frozen=True)
class TlsObservation:
    """What a TLS probe learned about a host's HTTPS service.

    `resolved=False` means the host has no public address, i.e. no web presence to judge. A host
    that resolves but refuses connections on the HTTPS port is `reachable=False`.
    """

    resolved: bool = True
    reachable: bool = True
    # One of "expired", "self_signed", "hostname_mismatch", "untrusted_chain"; None = trusted.
    cert_problem: str | None = None
    not_after: datetime | None = None  # certificate expiry (UTC); known when the chain is trusted
    protocol: str | None = None  # negotiated version, for example "TLSv1.3"
    legacy_protocols: tuple[str, ...] = ()  # protocols older than TLS 1.2 the server accepted
    modern_tls: bool = True  # False when the server accepts nothing newer than TLS 1.1


class TlsProbe(Protocol):
    def probe(self, host: str) -> TlsObservation: ...


@dataclass(frozen=True)
class WebResponse:
    """One HTTP response. Redirects are NOT followed; the caller decides whether to follow."""

    status: int
    headers: Mapping[str, str]  # header names lower-cased; repeated headers joined with ", "
    url: str


class WebClient(Protocol):
    def get(self, url: str) -> WebResponse | None:
        """GET `url`. None when there is nothing to talk to (no public address, connection
        refused). Raises on timeouts and other failures so a check fails instead of guessing."""
        ...


@dataclass(frozen=True)
class CheckContext:
    domain: str
    resolver: Resolver
    verified: bool = False  # True only when domain ownership has been proven
    tls: TlsProbe | None = None  # needed by checks that look at the HTTPS service
    web: WebClient | None = None  # needed by checks that fetch web pages


class Check(Protocol):
    key: str
    requires_verification: bool
    # Every finding key this check can produce. Each one must have an entry in the check library
    # (enforced by a test), so a check can never ship without plain-language text.
    emits: tuple[str, ...]

    def run(self, ctx: CheckContext) -> list[CheckResult]: ...


@dataclass(frozen=True)
class CheckResult:
    check_key: str  # stable id, matches a row in the check library
    severity: Severity
    exploitability: float  # 0..1, see the scoring model in the design document
    asset: str  # what it applies to, e.g. 'example.com'
    evidence: dict[str, object] = field(default_factory=dict)
    # 1.0 core internet-facing asset (main site, mail, VPN); 0.7 other internet-facing service;
    # 0.4 low-value or non-production subdomain.
    exposure: float = 1.0