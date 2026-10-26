from uuid import uuid4

import dns.resolver
import pytest
from django.db import connection

from apps.core.models import AuditLog
from apps.domains.models import Domain
from apps.findings.models import Finding
from apps.runner import services
from apps.runner.services import ExecutionResult
from apps.scans.models import Scan
from scanner import runner
from scanner.checks.email_auth import DmarcCheck
from scanner.dns import DnsPythonResolver
from scanner.types import CheckResult, Severity

from .conftest import FakeResolver

pytestmark = pytest.mark.usefixtures("library")

DMARC_NAME = "_dmarc.acme.example"


def execute(scan, resolver=None, checks=None):
    return services.execute_scan(
        tenant_id=scan.tenant_id,
        scan_id=scan.id,
        resolver=resolver or FakeResolver(),
        checks=checks,
    )


def make_scan(domain, mode=Scan.Mode.PASSIVE):
    return Scan.objects.create(
        tenant_id=domain.tenant_id, domain=domain, mode=mode, trigger_type=Scan.Trigger.MANUAL
    )


# ---- the happy path ----------------------------------------------------------------------------


def test_passive_scan_produces_findings_and_completes(queued_scan):
    assert execute(queued_scan) == ExecutionResult.SUCCEEDED

    queued_scan.refresh_from_db()
    assert queued_scan.status == Scan.Status.SUCCEEDED
    assert queued_scan.started_at
    assert queued_scan.finished_at
    assert queued_scan.scanner_version
    assert Finding.objects.get().check_definition.check_key == "EMAIL_DMARC_MISSING"

    event = AuditLog.objects.get(action="scan.completed", target_id=queued_scan.id)
    assert event.actor_type == "scanner"
    assert event.metadata["findings"]["new"] == 1
    assert event.metadata["failed_checks"] == []


def test_fixing_the_problem_and_rescanning_closes_the_finding(domain, queued_scan):
    execute(queued_scan)
    fixed = {DMARC_NAME: ["v=DMARC1; p=reject"]}
    assert execute(make_scan(domain), FakeResolver(fixed)) == ExecutionResult.SUCCEEDED
    assert Finding.objects.get().status == Finding.Status.FIXED


def test_active_scan_on_a_verified_domain_runs(verified_domain):
    scan = make_scan(verified_domain, Scan.Mode.ACTIVE)
    assert execute(scan) == ExecutionResult.SUCCEEDED


# ---- idempotency (messages are delivered at least once) ----------------------------------------


def test_a_redelivered_job_is_a_no_op(queued_scan):
    assert execute(queued_scan) == ExecutionResult.SUCCEEDED
    assert execute(queued_scan) == ExecutionResult.SKIPPED
    assert Finding.objects.count() == 1
    assert AuditLog.objects.filter(action="scan.completed").count() == 1


def test_a_scan_already_running_is_not_started_twice(queued_scan):
    Scan.objects.filter(id=queued_scan.id).update(status=Scan.Status.RUNNING)
    assert execute(queued_scan) == ExecutionResult.SKIPPED


def test_an_unknown_scan_is_skipped(tenant_a):
    result = services.execute_scan(tenant_id=tenant_a.id, scan_id=uuid4(), resolver=FakeResolver())
    assert result == ExecutionResult.SKIPPED


def test_another_tenants_scan_id_cannot_be_executed(queued_scan, tenant_b):
    result = services.execute_scan(
        tenant_id=tenant_b.id, scan_id=queued_scan.id, resolver=FakeResolver()
    )
    assert result == ExecutionResult.SKIPPED
    queued_scan.refresh_from_db()
    assert queued_scan.status == Scan.Status.QUEUED


# ---- failures never produce false findings or close real ones ----------------------------------


def test_a_dns_failure_fails_the_scan_and_never_creates_a_false_finding(queued_scan):
    result = execute(queued_scan, FakeResolver({DMARC_NAME: TimeoutError("dns timed out")}))

    assert result == ExecutionResult.FAILED
    queued_scan.refresh_from_db()
    assert queued_scan.status == Scan.Status.FAILED
    assert "EMAIL_DMARC" in queued_scan.error
    assert Finding.objects.count() == 0  # a timeout is NOT "DMARC is missing"


def test_a_dns_failure_never_closes_an_existing_finding(domain, queued_scan):
    execute(queued_scan)  # DMARC missing -> open finding
    flaky = FakeResolver({DMARC_NAME: TimeoutError("dns timed out")})
    assert execute(make_scan(domain), flaky) == ExecutionResult.FAILED
    assert Finding.objects.get().status == Finding.Status.OPEN


class _Broken:
    key = "BROKEN"
    requires_verification = False
    emits = ("BROKEN_FINDING",)

    def run(self, ctx):
        raise RuntimeError("boom")


def test_one_failing_check_gives_a_partial_scan_and_keeps_the_rest(queued_scan):
    assert execute(queued_scan, checks=[DmarcCheck(), _Broken()]) == ExecutionResult.PARTIAL
    queued_scan.refresh_from_db()
    assert queued_scan.status == Scan.Status.PARTIAL
    assert "BROKEN" in queued_scan.error
    assert Finding.objects.count() == 1


class _Unlisted:
    key = "UNLISTED"
    requires_verification = False
    emits = ("NOT_IN_LIBRARY",)

    def run(self, ctx):
        return [CheckResult("NOT_IN_LIBRARY", Severity.LOW, 0.5, ctx.domain)]


def test_a_check_without_library_text_fails_the_scan_cleanly(queued_scan):
    assert execute(queued_scan, checks=[_Unlisted()]) == ExecutionResult.FAILED
    queued_scan.refresh_from_db()
    assert queued_scan.status == Scan.Status.FAILED
    assert "ingest" in queued_scan.error
    assert Finding.objects.count() == 0


def test_an_unexpected_error_marks_the_scan_failed_and_is_raised(queued_scan, monkeypatch):
    def explode(*args, **kwargs):
        raise RuntimeError("bug")

    monkeypatch.setattr(runner, "run_checks", explode)
    with pytest.raises(RuntimeError):
        execute(queued_scan)
    queued_scan.refresh_from_db()
    assert queued_scan.status == Scan.Status.FAILED
    assert AuditLog.objects.filter(action="scan.failed", target_id=queued_scan.id).exists()


# ---- the database guard, reached through the worker --------------------------------------------


def test_an_active_scan_is_refused_when_verification_lapsed_after_queueing(verified_domain):
    scan = make_scan(verified_domain, Scan.Mode.ACTIVE)  # queued while verified...
    Domain.objects.filter(id=verified_domain.id).update(
        status=Domain.Status.EXPIRED
    )  # ...then lapses

    assert execute(scan) == ExecutionResult.REFUSED

    scan.refresh_from_db()
    assert scan.status == Scan.Status.REFUSED
    assert Finding.objects.count() == 0
    # The refusal audit row survives even though the guarded UPDATE was rolled back.
    event = AuditLog.objects.get(action="scan.refused", target_id=scan.id)
    assert event.metadata == {"reason": "domain_not_verified"}


def test_execution_holds_no_transaction_during_the_network_phase(queued_scan):
    """A slow DNS lookup must not keep a transaction (and its locks) open.

    pytest-django wraps each test in one transaction, so we measure nesting depth: the claim and
    finish phases each open an atomic block (a savepoint here), and neither may be open while the
    checks run.
    """
    depth_during_checks = []

    class Probe:
        key = "PROBE"
        requires_verification = False
        emits = ()

        def run(self, ctx):
            depth_during_checks.append(len(connection.savepoint_ids))
            return []

    baseline = len(connection.savepoint_ids)
    services.execute_scan(
        tenant_id=queued_scan.tenant_id,
        scan_id=queued_scan.id,
        resolver=FakeResolver(),
        checks=[Probe()],
    )
    assert depth_during_checks == [baseline]


def test_a_hijacked_resolver_cannot_create_false_findings_or_close_real_ones(domain, queued_scan):
    """Regression: a resolver answering NXDOMAIN for everything (captive portal, egress block)
    used to read as 'no DMARC record anywhere'."""
    execute(queued_scan, FakeResolver({DMARC_NAME: ["v=DMARC1; p=none"]}))  # real: monitor-only
    assert Finding.objects.get().check_definition.check_key == "EMAIL_DMARC_MONITOR_ONLY"

    def nxdomain(name, rtype):
        raise dns.resolver.NXDOMAIN

    sinkhole = DnsPythonResolver()
    sinkhole._resolver.resolve = nxdomain
    assert execute(make_scan(domain), sinkhole) == ExecutionResult.FAILED

    finding = Finding.objects.get()  # still exactly one, and still open
    assert finding.check_definition.check_key == "EMAIL_DMARC_MONITOR_ONLY"
    assert finding.status == Finding.Status.OPEN