"""Read-only queries."""

from uuid import UUID

from django.db.models import F, QuerySet

from apps.scans.models import Scan

from .models import Report


def latest_completed_scan(*, tenant_id: UUID, domain_id: UUID) -> Scan | None:
    """The newest scan whose results are in the findings table (succeeded, or partial)."""
    return (
        Scan.objects.filter(
            tenant_id=tenant_id,
            domain_id=domain_id,
            status__in=[Scan.Status.SUCCEEDED, Scan.Status.PARTIAL],
        )
        .order_by(F("finished_at").desc(nulls_last=True), "-queued_at")
        .first()
    )


def latest_report(*, tenant_id: UUID, domain_id: UUID) -> Report | None:
    return (
        Report.objects.filter(tenant_id=tenant_id, domain_id=domain_id)
        .defer("snapshot")
        .order_by("-generated_at")
        .first()
    )


def list_reports(*, tenant_id: UUID, domain_id: UUID, limit: int = 50) -> QuerySet[Report]:
    # The snapshot can be large and lists never show it.
    return (
        Report.objects.filter(tenant_id=tenant_id, domain_id=domain_id)
        .defer("snapshot")
        .order_by("-generated_at")[:limit]
    )


def get_report(*, tenant_id: UUID, report_id: UUID, with_snapshot: bool = False) -> Report | None:
    qs = Report.objects.filter(tenant_id=tenant_id, id=report_id)
    if not with_snapshot:
        qs = qs.defer("snapshot")
    return qs.first()