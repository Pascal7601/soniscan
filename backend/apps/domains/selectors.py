from uuid import UUID

from django.db.models import QuerySet

from .models import Domain


def list_domains(tenant_id: UUID) -> QuerySet[Domain]:
    # Filtering by tenant is redundant with row-level security on purpose: two independent layers.
    return Domain.objects.filter(tenant_id=tenant_id).order_by("fqdn")


def get_domain(*, tenant_id: UUID, domain_id: UUID) -> Domain | None:
    return Domain.objects.filter(tenant_id=tenant_id, id=domain_id).first()
