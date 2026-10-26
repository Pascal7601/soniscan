"""Run a set of checks against one target. Pure orchestration, no framework imports.

Guarantees:
  * a check that raises is recorded as a failure and contributes NO results and NO coverage, so a
    flaky lookup can never create false findings or close real ones;
  * one failing check never stops the others;
  * a check that requires ownership verification refuses to run against an unverified target.
"""

from collections.abc import Iterable
from dataclasses import dataclass, field

from . import registry
from .types import Check, CheckContext, CheckResult


class VerificationRequired(Exception):
    """A verification-only check was scheduled against an unverified domain (a bug)."""


@dataclass(frozen=True)
class CheckFailure:
    check_key: str
    error: str  # exception class and a short message; internal diagnostics only


@dataclass
class RunOutcome:
    results: list[CheckResult] = field(default_factory=list)
    covered_keys: set[str] = field(default_factory=set)  # finding keys of checks that COMPLETED
    completed: list[str] = field(default_factory=list)
    failures: list[CheckFailure] = field(default_factory=list)


def select_checks(*, active: bool, verified: bool) -> list[Check]:
    """Passive scans run checks that need no proof of ownership; active scans run everything."""
    if not active:
        return registry.passive_checks()
    if not verified:
        raise VerificationRequired("active checks require a verified domain")
    return registry.all_checks()


def run_checks(checks: Iterable[Check], ctx: CheckContext) -> RunOutcome:
    outcome = RunOutcome()
    for check in checks:
        if check.requires_verification and not ctx.verified:
            raise VerificationRequired(f"{check.key} requires a verified domain")
        try:
            results = check.run(ctx)
        except Exception as exc:  # noqa: BLE001 - isolate every failure to its own check
            outcome.failures.append(CheckFailure(check.key, f"{type(exc).__name__}: {exc}"[:300]))
            continue
        outcome.results.extend(results)
        outcome.covered_keys |= set(check.emits)
        outcome.completed.append(check.key)
    return outcome