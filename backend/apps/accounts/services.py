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
