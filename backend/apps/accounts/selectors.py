"""Read-only queries. No side effects."""

from uuid import UUID

from django.db.models import QuerySet

from .models import Membership


def memberships_for_user(user_id: UUID) -> QuerySet[Membership]:
    return (
        Membership.objects.filter(user_id=user_id).select_related("tenant").order_by("created_at")
    )
