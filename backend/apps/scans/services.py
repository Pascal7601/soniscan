"""Scan business rules. The database trigger is the last line of defence; these checks come
first so users get a clear error instead of a constraint violation."""

from datetime import datetime
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from apps.accounts.models import Tenant
from apps.core import audit
from apps.domains.models import Domain
from apps.core.tasks import dispatch_on_commit

from .models import Scan

RUN_SCAN_TASK = "runner.run_scan"
PLAN_MAX_SCANS_PER_MONTH = {"free": 3, "starter": 30, "business": 150}
PLAN_ALLOWS_ACTIVE = {"free": False, "starter": True, "business": True}


class ScanError(Exception):
    """Base class for scan rule violations (mapped to HTTP errors at the API layer).

    Refusals are NOT audited here: raising inside @transaction.atomic rolls the audit row back.
    The API layer records `scan.refused` and returns a normal response so the row is committed.
    """


class DomainNotVerified(ScanError):
    pass


class ActiveScansNotInPlan(ScanError):
    pass


class ScanQuotaExceeded(ScanError):
    pass


def _month_start(now: datetime) -> datetime:
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


@transaction.atomic
def request_scan(
    *,
    domain: Domain,
    mode: str,
    actor_id: UUID | None = None,
    trigger_type: str = Scan.Trigger.MANUAL,
) -> Scan:
    # Lock the tenant row so two concurrent requests cannot both pass the quota check.
    tenant = Tenant.objects.select_for_update().get(id=domain.tenant_id)

    if mode == Scan.Mode.ACTIVE:
        if not PLAN_ALLOWS_ACTIVE[tenant.plan]:
            raise ActiveScansNotInPlan("Active scans are not included in your plan.")
        if not domain.is_verified_now():
            raise DomainNotVerified("Verify ownership of this domain before running active scans.")

    used = (
        Scan.objects.filter(tenant_id=tenant.id, queued_at__gte=_month_start(timezone.now()))
        .exclude(status__in=[Scan.Status.REFUSED, Scan.Status.FAILED])
        .count()
    )
    limit = PLAN_MAX_SCANS_PER_MONTH[tenant.plan]
    if used >= limit:
        raise ScanQuotaExceeded(f"Your plan allows {limit} scans per month.")

    scan = Scan.objects.create(
        tenant_id=tenant.id,
        domain=domain,
        mode=mode,
        trigger_type=trigger_type,
        requested_by_id=actor_id,
    )
    audit.record(
        action="scan.requested",
        actor_id=actor_id,
        tenant_id=tenant.id,
        target_type="scan",
        target_id=scan.id,
        metadata={"mode": mode, "domain": domain.fqdn, "trigger": trigger_type},
    )
    dispatch_on_commit(RUN_SCAN_TASK, str(tenant.id), str(scan.id))
    return scan
    # Step 3 will enqueue execution here:
    #   transaction.on_commit(lambda: run_scan.delay(str(tenant.id), str(scan.id)))
    return scan