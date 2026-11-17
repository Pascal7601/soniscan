"""Write operations and business rules. Views call services; services never touch HTTP."""

from django.db import transaction

from apps.core.tenancy import activate

from .models import Membership, Tenant, User


@transaction.atomic
def create_tenant_with_owner(*, owner: User, name: str) -> Tenant:
    """Create an organisation and make `owner` its first owner.

    Shows the pattern for the one moment a tenant has no context yet: create the tenant row
    (the tenants table is global), then activate its context before writing tenant-owned rows.
    """
    tenant = Tenant.objects.create(name=name)
    activate(user_id=owner.id, tenant_id=tenant.id)
    Membership.objects.create(tenant=tenant, user=owner, role=Membership.Role.OWNER)
    return tenant

def default_organisation_name(user: User) -> str:
    return f"{user.display_name or user.email.split('@')[0]}'s organisation"


@transaction.atomic
def ensure_organisation(*, user: User, name: str = "") -> Tenant:
    """Give a brand-new user their first organisation, with them as owner.

    Idempotent: a user who already belongs to one gets that one back. Sign-up calls this from two
    places (the sign-up form, which knows the organisation name, and the user_signed_up signal,
    which also covers social sign-up) and whichever runs first wins.
    """
    activate(user_id=user.id)  # lets us read the user's own memberships under row-level security
    existing = Membership.objects.filter(user_id=user.id).select_related("tenant").first()
    if existing is not None:
        return existing.tenant
    return create_tenant_with_owner(owner=user, name=name.strip() or default_organisation_name(user))