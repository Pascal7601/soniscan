from datetime import timedelta

import dns.exception
import pytest
from django.utils import timezone

from apps.core.models import AuditLog
from apps.domains import services as domain_services
from apps.domains.models import Domain, DomainVerification
from apps.runner import services
from apps.runner.services import VerificationOutcome
from apps.scans import services as scan_services
from apps.scans.models import Scan

from .conftest import FakeResolver

# ---- reaper ------------------------------------------------------------------------------------


def _scan(domain, **kwargs):
    return Scan.objects.create(
        tenant_id=domain.tenant_id,
        domain=domain,
        mode=Scan.Mode.PASSIVE,
        trigger_type=Scan.Trigger.MANUAL,
        **kwargs,
    )


def test_stuck_running_scans_are_failed(domain):
    old = timezone.now() - services.STALE_RUNNING_AFTER - timedelta(minutes=1)
    stuck = _scan(domain, status=Scan.Status.RUNNING, started_at=old)
    fresh = _scan(domain, status=Scan.Status.RUNNING, started_at=timezone.now())

    assert services.reap_stale_scans() == 1

    stuck.refresh_from_db()
    fresh.refresh_from_db()
    assert stuck.status == Scan.Status.FAILED
    assert "worker_lost" in stuck.error
    assert fresh.status == Scan.Status.RUNNING
    assert AuditLog.objects.filter(action="scan.failed", target_id=stuck.id).exists()


def test_scans_that_were_never_picked_up_are_failed(domain):
    scan = _scan(
        domain, queued_at=timezone.now() - services.STALE_QUEUED_AFTER - timedelta(minutes=1)
    )
    assert services.reap_stale_scans() == 1
    scan.refresh_from_db()
    assert scan.status == Scan.Status.FAILED
    assert "never_started" in scan.error


def test_finished_and_recent_scans_are_left_alone(domain):
    _scan(domain, status=Scan.Status.SUCCEEDED, queued_at=timezone.now() - timedelta(days=3))
    _scan(domain)  # queued just now
    assert services.reap_stale_scans() == 0


def test_a_reaped_scan_does_not_use_up_the_monthly_quota(domain):
    for _ in range(scan_services.PLAN_MAX_SCANS_PER_MONTH["free"]):
        _scan(domain, status=Scan.Status.FAILED)
    scan = scan_services.request_scan(domain=domain, mode=Scan.Mode.PASSIVE)
    assert scan.status == Scan.Status.QUEUED


# ---- domain verification checks ----------------------------------------------------------------

RECORD = "_posture-verify.acme.example"


@pytest.fixture
def pending(domain):
    verification, token = domain_services.start_verification(domain=domain)
    return verification, f"{domain_services.TXT_PREFIX}{token}"


def check(domain, resolver):
    return services.check_domain_verification(
        tenant_id=domain.tenant_id, domain_id=domain.id, resolver=resolver
    )


def test_the_right_record_verifies_the_domain(domain, pending):
    _, value = pending
    assert check(domain, FakeResolver({RECORD: [value]})) == VerificationOutcome.VERIFIED
    domain.refresh_from_db()
    assert domain.status == Domain.Status.VERIFIED
    assert domain.is_verified_now()
    assert AuditLog.objects.filter(action="domain.verified", target_id=domain.id).exists()


def test_a_missing_record_keeps_the_attempt_alive_until_dns_catches_up(domain, pending):
    """DNS changes take minutes to propagate: the first check usually misses, the next hits."""
    verification, value = pending

    assert check(domain, FakeResolver({})) == VerificationOutcome.NOT_FOUND
    verification.refresh_from_db()
    assert verification.result == DomainVerification.Result.PENDING
    assert verification.checked_at is not None

    assert check(domain, FakeResolver({RECORD: [value]})) == VerificationOutcome.VERIFIED


def test_a_wrong_token_does_not_verify(domain, pending):
    wrong = f"{domain_services.TXT_PREFIX}not-the-token"
    assert check(domain, FakeResolver({RECORD: [wrong]})) == VerificationOutcome.NOT_FOUND
    domain.refresh_from_db()
    assert domain.status == Domain.Status.PENDING


def test_a_dns_error_is_not_treated_as_a_missing_record(domain, pending):
    resolver = FakeResolver({RECORD: dns.exception.Timeout})
    assert check(domain, resolver) == VerificationOutcome.DNS_ERROR
    event = AuditLog.objects.get(action="domain.verification_check_failed")
    assert event.metadata == {"reason": "dns_error"}


def test_an_expired_attempt_is_reported_as_expired(domain, pending):
    verification, value = pending
    DomainVerification.objects.filter(id=verification.id).update(
        expires_at=timezone.now() - timedelta(minutes=1)
    )
    assert check(domain, FakeResolver({RECORD: [value]})) == VerificationOutcome.EXPIRED
    domain.refresh_from_db()
    assert domain.status == Domain.Status.PENDING


def test_nothing_to_check_without_a_pending_attempt(domain):
    assert check(domain, FakeResolver({})) == VerificationOutcome.NO_PENDING


def test_another_tenant_cannot_check_your_domain(domain, pending, tenant_b):
    outcome = services.check_domain_verification(
        tenant_id=tenant_b.id, domain_id=domain.id, resolver=FakeResolver({})
    )
    assert outcome == VerificationOutcome.NO_PENDING


def test_a_second_organisation_cannot_claim_a_verified_domain(domain, pending, tenant_b):
    _, value = pending
    assert check(domain, FakeResolver({RECORD: [value]})) == VerificationOutcome.VERIFIED

    other = Domain.objects.create(tenant=tenant_b, fqdn="acme.example")
    _, token = domain_services.start_verification(domain=other)
    resolver = FakeResolver({RECORD: [f"{domain_services.TXT_PREFIX}{token}"]})

    assert check(other, resolver) == VerificationOutcome.ALREADY_CLAIMED
    other.refresh_from_db()
    assert other.status == Domain.Status.PENDING
    # The conflict is audited even though the claim attempt itself was rolled back.
    conflict = AuditLog.objects.filter(action="domain.verification_conflict", target_id=other.id)
    assert conflict.exists()