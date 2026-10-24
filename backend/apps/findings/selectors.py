"""Read-only queries."""

from uuid import UUID

from django.db.models import Case, IntegerField, QuerySet, Value, When

from .models import Finding, ScoringModel

_EFFORT_RANK = Case(
    When(check_definition__effort="minutes", then=Value(1)),
    When(check_definition__effort="hours", then=Value(2)),
    default=Value(3),
    output_field=IntegerField(),
)


def current_scoring_model() -> ScoringModel:
    model = ScoringModel.objects.order_by("-version").first()
    if model is None:
        raise RuntimeError("no scoring model found; run migrations")
    return model


def list_findings(
    *, tenant_id: UUID, domain_id: UUID, status: str | None = "open"
) -> QuerySet[Finding]:
    qs = Finding.objects.filter(tenant_id=tenant_id, domain_id=domain_id).select_related(
        "check_definition"
    )
    if status:
        qs = qs.filter(status=status)
    return qs.order_by("-score", "asset")


def fix_first(*, tenant_id: UUID, domain_id: UUID, limit: int = 5) -> QuerySet[Finding]:
    """Open findings ranked by score (highest first), ties broken by lowest effort."""
    return (
        list_findings(tenant_id=tenant_id, domain_id=domain_id, status="open")
        .annotate(effort_rank=_EFFORT_RANK)
        .order_by("-score", "effort_rank", "asset")[:limit]
    )


def get_finding(*, tenant_id: UUID, finding_id: UUID) -> Finding | None:
    return (
        Finding.objects.filter(tenant_id=tenant_id, id=finding_id)
        .select_related("check_definition")
        .first()
    )