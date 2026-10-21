import uuid

from django.db import models


class BaseModel(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class TenantOwnedModel(BaseModel):
    """Base for every table that belongs to a customer organisation.

    Subclasses MUST get row-level security in their migrations:
        core.db.enable_tenant_rls("<table>")
    and a tenant-isolation test in tests/.
    """

    tenant = models.ForeignKey("accounts.Tenant", on_delete=models.CASCADE)

    class Meta:
        abstract = True
