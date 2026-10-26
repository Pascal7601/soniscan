import pytest

from scanner import runner
from scanner.runner import VerificationRequired, run_checks, select_checks
from scanner.types import CheckContext, CheckResult, Severity


class Resolver:
    def txt(self, name):
        return []


class Good:
    key = "GOOD"
    requires_verification = False
    emits = ("GOOD_FINDING",)

    def run(self, ctx):
        return [CheckResult("GOOD_FINDING", Severity.LOW, 0.5, ctx.domain)]


class Broken:
    key = "BROKEN"
    requires_verification = False
    emits = ("BROKEN_FINDING",)

    def run(self, ctx):
        raise TimeoutError("dns timed out")


class NeedsVerification:
    key = "ACTIVE"
    requires_verification = True
    emits = ("ACTIVE_FINDING",)

    def run(self, ctx):
        return []


def ctx(verified=False):
    return CheckContext("acme.example", Resolver(), verified=verified)


def test_results_and_coverage_come_from_completed_checks():
    outcome = run_checks([Good()], ctx())
    assert [r.check_key for r in outcome.results] == ["GOOD_FINDING"]
    assert outcome.covered_keys == {"GOOD_FINDING"}
    assert outcome.completed == ["GOOD"]
    assert outcome.failures == []


def test_a_failing_check_is_isolated_and_gets_no_coverage():
    outcome = run_checks([Broken(), Good()], ctx())
    assert [r.check_key for r in outcome.results] == ["GOOD_FINDING"]
    assert outcome.covered_keys == {"GOOD_FINDING"}  # BROKEN_FINDING can never be "fixed" by this run
    assert [f.check_key for f in outcome.failures] == ["BROKEN"]
    assert "TimeoutError" in outcome.failures[0].error


def test_verification_only_checks_refuse_unverified_targets():
    with pytest.raises(VerificationRequired):
        run_checks([NeedsVerification()], ctx(verified=False))


def test_verification_only_checks_run_on_verified_targets():
    assert run_checks([NeedsVerification()], ctx(verified=True)).completed == ["ACTIVE"]


def test_active_selection_requires_verification():
    with pytest.raises(VerificationRequired):
        select_checks(active=True, verified=False)


def test_passive_selection_never_includes_verification_only_checks():
    import scanner.checks  # noqa: F401  (registers checks)

    assert all(not c.requires_verification for c in select_checks(active=False, verified=False))
    assert runner.registry.passive_checks()