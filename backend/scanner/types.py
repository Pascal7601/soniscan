"""Plain data types shared by all checks. No framework imports allowed in this package."""

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Protocol


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


@dataclass(frozen=True)
class CheckContext:
    domain: str
    resolver: Resolver
    verified: bool = False  # True only when domain ownership has been proven


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