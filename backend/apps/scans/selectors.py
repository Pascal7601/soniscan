from uuid import UUID

from django.db.models import QuerySet

from .models import Scan


def list_scans(*, tenant_id: UUID, domain_id: UUID, limit: int = 50) -> QuerySet[Scan]:
    return Scan.objects.filter(tenant_id=tenant_id, domain_id=domain_id).order_by("-queued_at")[
        :limit
    ]


def get_scan(*, tenant_id: UUID, scan_id: UUID) -> Scan | None:
    return Scan.objects.filter(tenant_id=tenant_id, id=scan_id).first()