from datetime import timedelta

import pytest
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.accounts.models import Tenant
from apps.core.models import AuditLog
from apps.domains.models import Domain
from apps.scans import services
from apps.scans.models import Scan


def _scan(domain, mode, **kwargs):
    return Scan.objects.create(
        tenant_id=domain.tenant_id,
        domain=domain,
        mode=mode,
        trigger_type=Scan.Trigger.MANUAL,
        **kwargs,
    )


# ---- the database guard (cannot be bypassed from any code path) --------------------------------


def test_db_refuses_active_scan_on_unverified_domain(tenant_a):
    domain = Domain.objects.create(tenant=tenant_a, fqdn="unverified.example")
    with pytest.raises(IntegrityError, match="not currently verified"), transaction.atomic():
        _scan(domain, Scan.Mode.ACTIVE)


def test_db_allows_passive_scan_on_unverified_domain(tenant_a):
    domain = Domain.objects.create(tenant=tenant_a, fqdn="unverified.example")
    assert _scan(domain, Scan.Mode.PASSIVE).status == Scan.Status.QUEUED


def test_db_allows_active_scan_on_verified_domain(verified_domain):
    assert _scan(verified_domain, Scan.Mode.ACTIVE).mode == Scan.Mode.ACTIVE


def test_db_refuses_active_scan_when_verification_lapsed(verified_domain):
    Domain.objects.filter(id=verified_domain.id).update(
        reverify_due=timezone.now() - timedelta(days=1)
    )
    with pytest.raises(IntegrityError, match="not currently verified"), transaction.atomic():
        _scan(verified_domain, Scan.Mode.ACTIVE)


def test_db_refuses_switching_an_existing_scan_to_active(tenant_a):
    domain = Domain.objects.create(tenant=tenant_a, fqdn="unverified.example")
    scan = _scan(domain, Scan.Mode.PASSIVE)
    with pytest.raises(IntegrityError, match="not currently verified"), transaction.atomic():
        Scan.objects.filter(id=scan.id).update(mode=Scan.Mode.ACTIVE)


def test_scan_cannot_reference_another_tenants_domain(tenant_a, tenant_b):
    domain_a = Domain.objects.create(tenant=tenant_a, fqdn="a.example")
    with pytest.raises(IntegrityError), transaction.atomic():
        Scan.objects.create(tenant=tenant_b, domain=domain_a, mode="passive", trigger_type="manual")


# ---- service rules -----------------------------------------------------------------------------


@pytest.fixture
def starter(tenant_a):
    tenant_a.plan = Tenant.Plan.STARTER
    tenant_a.save()
    return tenant_a


def test_service_gives_a_clear_error_for_unverified_active_scan(starter):
    domain = Domain.objects.create(tenant=starter, fqdn="unverified.example")
    with pytest.raises(services.DomainNotVerified):
        services.request_scan(domain=domain, mode=Scan.Mode.ACTIVE)


def test_free_plan_cannot_run_active_scans(verified_domain):
    with pytest.raises(services.ActiveScansNotInPlan):
        services.request_scan(domain=verified_domain, mode=Scan.Mode.ACTIVE)


def test_request_scan_creates_scan_and_audit_event(starter, verified_domain, user_a):
    scan = services.request_scan(domain=verified_domain, mode=Scan.Mode.ACTIVE, actor_id=user_a.id)
    assert scan.status == Scan.Status.QUEUED
    event = AuditLog.objects.get(action="scan.requested", target_id=scan.id)
    assert event.actor_id == user_a.id
    assert event.metadata["mode"] == "active"


def test_monthly_quota_is_enforced(tenant_a):
    domain = Domain.objects.create(tenant=tenant_a, fqdn="q.example")
    for _ in range(services.PLAN_MAX_SCANS_PER_MONTH["free"]):
        services.request_scan(domain=domain, mode=Scan.Mode.PASSIVE)
    with pytest.raises(services.ScanQuotaExceeded):
        services.request_scan(domain=domain, mode=Scan.Mode.PASSIVE)


def test_refused_scans_do_not_consume_quota(tenant_a):
    domain = Domain.objects.create(tenant=tenant_a, fqdn="q.example")
    for _ in range(services.PLAN_MAX_SCANS_PER_MONTH["free"]):
        _scan(domain, Scan.Mode.PASSIVE, status=Scan.Status.REFUSED)
    services.request_scan(domain=domain, mode=Scan.Mode.PASSIVE)