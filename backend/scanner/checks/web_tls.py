"""TLS and certificate check: is the HTTPS service there, trusted, current and modern?

`evaluate_tls` is a pure function of what a TLS probe observed and the current time. The probe
(`scanner.net.StdlibTlsProbe`) does the networking and is passed in through the check context.
"""

from collections.abc import Callable
from datetime import UTC, datetime

from scanner.registry import register
from scanner.types import (
    CapabilityMissing,
    CheckContext,
    CheckResult,
    Severity,
    TlsObservation,
)

URGENT_DAYS = 7
SOON_DAYS = 30

# certificate problem -> (finding key, severity, exploitability)
_CERT_PROBLEMS = {
    "expired": ("TLS_CERT_EXPIRED", Severity.HIGH, 1.0),
    "self_signed": ("TLS_CERT_SELF_SIGNED", Severity.HIGH, 0.8),
    "hostname_mismatch": ("TLS_CERT_HOSTNAME_MISMATCH", Severity.HIGH, 0.8),
    "untrusted_chain": ("TLS_CERT_UNTRUSTED_CHAIN", Severity.MEDIUM, 0.6),
}


def evaluate_tls(domain: str, observed: TlsObservation, now: datetime) -> list[CheckResult]:
    if not observed.resolved:
        return []  # no public address, so no website to judge
    if not observed.reachable:
        return [CheckResult("TLS_NOT_AVAILABLE", Severity.MEDIUM, 0.6, domain)]

    results: list[CheckResult] = []
    if observed.cert_problem is not None:
        # An unknown problem name is a bug; the KeyError fails the check instead of guessing.
        key, severity, exploitability = _CERT_PROBLEMS[observed.cert_problem]
        results.append(CheckResult(key, severity, exploitability, domain))
    elif observed.not_after is not None:
        days_left = int((observed.not_after - now).total_seconds() // 86400)
        evidence: dict[str, object] = {
            "days_left": days_left,
            "expires": observed.not_after.date().isoformat(),
        }
        if days_left < 0:
            results.append(CheckResult("TLS_CERT_EXPIRED", Severity.HIGH, 1.0, domain, evidence))
        elif days_left <= URGENT_DAYS:
            results.append(
                CheckResult("TLS_CERT_EXPIRING_SOON", Severity.HIGH, 0.9, domain, evidence)
            )
        elif days_left <= SOON_DAYS:
            results.append(
                CheckResult("TLS_CERT_EXPIRING_SOON", Severity.MEDIUM, 0.7, domain, evidence)
            )

    if observed.legacy_protocols:
        # Nothing newer than TLS 1.1 at all means modern browsers cannot connect: more serious.
        severity, exploitability = (
            (Severity.MEDIUM, 0.4) if observed.modern_tls else (Severity.HIGH, 0.5)
        )
        legacy: dict[str, object] = {
            "protocols": list(observed.legacy_protocols),
            "modern_tls": observed.modern_tls,
        }
        results.append(CheckResult("TLS_LEGACY_PROTOCOL", severity, exploitability, domain, legacy))
    return results


class TlsCheck:
    key = "WEB_TLS"
    requires_verification = False
    emits: tuple[str, ...] = (
        "TLS_NOT_AVAILABLE",
        "TLS_CERT_EXPIRED",
        "TLS_CERT_EXPIRING_SOON",
        "TLS_CERT_SELF_SIGNED",
        "TLS_CERT_HOSTNAME_MISMATCH",
        "TLS_CERT_UNTRUSTED_CHAIN",
        "TLS_LEGACY_PROTOCOL",
    )

    def __init__(self, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    def run(self, ctx: CheckContext) -> list[CheckResult]:
        if ctx.tls is None:
            raise CapabilityMissing("WEB_TLS needs a TLS probe in the check context")
        return evaluate_tls(ctx.domain, ctx.tls.probe(ctx.domain), self._clock())


register(TlsCheck())