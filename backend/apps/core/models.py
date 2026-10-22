import uuid

from django.db import models
from django.utils import timezone


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


class AuditLog(models.Model):
    """Append-only security event log. Immutability is enforced by database triggers.

    Write ONLY through apps.core.audit.record(). tenant_id is deliberately not a foreign key:
    history must outlive the organisation it describes.
    """

    class ActorType(models.TextChoices):
        USER = "user"
        SYSTEM = "system"
        SCANNER = "scanner"

    occurred_at = models.DateTimeField(default=timezone.now)
    tenant_id = models.UUIDField(null=True, blank=True)
    actor_type = models.CharField(max_length=20, choices=ActorType.choices)
    actor_id = models.UUIDField(null=True, blank=True)
    action = models.CharField(max_length=100)  # e.g. domain.verified, scan.requested
    target_type = models.CharField(max_length=50, blank=True)
    target_id = models.UUIDField(null=True, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=300, blank=True)
    metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        db_table = "audit_log"
        indexes = [
            models.Index(fields=["tenant_id", "-occurred_at"], name="audit_log_tenant_time_idx")
        ]

    def __str__(self) -> str:
        return f"{self.action} @ {self.occurred_at:%Y-%m-%d %H:%M:%S}"