from django.conf import settings
from django.db import models
from django.db.models import Q
from django.utils import timezone

from apps.core.models import TenantOwnedModel
from apps.domains.models import Domain
from apps.findings.models import ScoringModel
from apps.scans.models import Scan


class Report(TenantOwnedModel):
    """A frozen record of one domain's security posture at one moment.

    `snapshot` holds everything the customer was shown (scores, and the exact library text), so a
    report never changes when findings are fixed or the library wording is improved. The PDF is
    NOT stored: it is rendered from the snapshot on demand (apps.reports.pdf), which keeps one
    source of truth and needs no file storage. A database trigger (migration 0002) makes rows
    immutable; `content_sha256` lets a download detect tampering by anyone with owner access.
    """

    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="reports")
    scan = models.ForeignKey(Scan, on_delete=models.RESTRICT, related_name="+")
    scoring_model = models.ForeignKey(ScoringModel, on_delete=models.PROTECT, related_name="+")
    generated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    generated_at = models.DateTimeField(default=timezone.now)
    # Denormalised from the snapshot so lists and trend lines need no JSON parsing.
    score = models.PositiveSmallIntegerField()
    grade = models.CharField(max_length=1)
    open_findings = models.PositiveIntegerField()
    snapshot_version = models.PositiveSmallIntegerField()
    snapshot = models.JSONField()
    content_sha256 = models.CharField(max_length=64)

    class Meta:
        db_table = "reports"
        constraints = [
            models.UniqueConstraint(fields=["id", "tenant"], name="reports_id_tenant_uniq"),
            models.CheckConstraint(
                condition=Q(score__gte=0, score__lte=100), name="reports_score_range"
            ),
        ]
        indexes = [models.Index(fields=["domain", "-generated_at"], name="reports_domain_time_idx")]