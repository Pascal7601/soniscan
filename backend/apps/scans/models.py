from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.core.models import TenantOwnedModel
from apps.domains.models import Domain


class Scan(TenantOwnedModel):
    class Mode(models.TextChoices):
        PASSIVE = "passive"
        ACTIVE = "active"

    class Trigger(models.TextChoices):
        MANUAL = "manual"
        SCHEDULED = "scheduled"

    class Status(models.TextChoices):
        QUEUED = "queued"
        RUNNING = "running"
        SUCCEEDED = "succeeded"
        PARTIAL = "partial"
        FAILED = "failed"
        CANCELLED = "cancelled"
        REFUSED = "refused"

    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="scans")
    trigger_type = models.CharField(max_length=20, choices=Trigger.choices)
    mode = models.CharField(max_length=20, choices=Mode.choices)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.QUEUED)
    requested_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL
    )
    scanner_version = models.CharField(max_length=50, blank=True)
    queued_at = models.DateTimeField(default=timezone.now)
    started_at = models.DateTimeField(null=True, blank=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    error = models.TextField(blank=True)  # internal diagnostics; never exposed by the API
    raw_output_key = models.CharField(max_length=300, blank=True)
    raw_expires_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "scans"
        constraints = [
            # Target of composite foreign keys from findings/reports (tenant consistency).
            models.UniqueConstraint(fields=["id", "tenant"], name="scans_id_tenant_uniq"),
        ]
        indexes = [
            models.Index(fields=["domain", "-queued_at"], name="scans_domain_queued_idx"),
            models.Index(
                fields=["status"],
                condition=Q(status__in=["queued", "running"]),
                name="scans_pending_idx",
            ),
        ]