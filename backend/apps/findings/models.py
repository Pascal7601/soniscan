from django.conf import settings
from django.db import models
from django.db.models import Q

from apps.core.models import BaseModel, TenantOwnedModel
from apps.domains.models import Domain
from apps.scans.models import Scan

SEVERITY_CHOICES = [
    ("critical", "Critical"),
    ("high", "High"),
    ("medium", "Medium"),
    ("low", "Low"),
    ("info", "Info"),
]


class CheckDefinition(BaseModel):
    """One version of the plain-language text for a check. Global (not tenant data), read-only
    for the application role; written only by `sync_check_library`, which runs as the owner."""

    class Category(models.TextChoices):
        EMAIL = "email"
        TLS = "tls"
        WEB = "web"
        SUBDOMAIN = "subdomain"
        EXPOSED_SERVICE = "exposed_service"
        SOFTWARE = "software"
        CREDENTIALS = "credentials"

    class Effort(models.TextChoices):
        MINUTES = "minutes"
        HOURS = "hours"
        DAYS = "days"

    check_key = models.CharField(max_length=80)
    version = models.PositiveIntegerField()
    category = models.CharField(max_length=30, choices=Category.choices)
    requires_verification = models.BooleanField()  # active checks and breach lookups
    title = models.CharField(max_length=200)
    severity_base = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    exploitability_base = models.DecimalField(max_digits=3, decimal_places=2)
    plain_explanation = models.TextField()
    why_it_matters = models.TextField()
    fix_steps = models.JSONField()  # ordered list of strings
    effort = models.CharField(max_length=10, choices=Effort.choices)
    owner_hint = models.CharField(max_length=200, blank=True)
    reference_links = models.JSONField(default=list, blank=True)
    content_hash = models.CharField(max_length=64)
    is_active = models.BooleanField(default=True)

    class Meta:
        db_table = "check_definitions"
        constraints = [
            models.UniqueConstraint(
                fields=["check_key", "version"], name="checkdef_key_version_uniq"
            ),
            models.CheckConstraint(
                condition=Q(exploitability_base__gte=0, exploitability_base__lte=1),
                name="checkdef_exploitability_range",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.check_key} v{self.version}"


class ScoringModel(models.Model):
    """Versioned scoring constants (see scanner.scoring). Global and read-only for the app."""

    version = models.PositiveIntegerField(primary_key=True)
    params = models.JSONField()
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "scoring_models"

    def __str__(self) -> str:
        return f"scoring model v{self.version}"


class Finding(TenantOwnedModel):
    """A security issue's lifecycle across scans. Per-scan evidence lives in FindingObservation."""

    class Status(models.TextChoices):
        OPEN = "open"
        FIXED = "fixed"
        ACCEPTED_RISK = "accepted_risk"
        FALSE_POSITIVE = "false_positive"

    domain = models.ForeignKey(Domain, on_delete=models.CASCADE)
    check_definition = models.ForeignKey(CheckDefinition, on_delete=models.PROTECT)
    # e.g. 'example.com'. A separate assets table arrives with active scans.
    asset = models.CharField(max_length=253)
    fingerprint = models.CharField(max_length=64)  # sha256(check_key | asset): stable across scans
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    exploitability = models.DecimalField(max_digits=3, decimal_places=2)
    exposure = models.DecimalField(max_digits=3, decimal_places=2)
    score = models.DecimalField(max_digits=4, decimal_places=2)  # from the latest observation
    first_seen_scan = models.ForeignKey(Scan, on_delete=models.RESTRICT, related_name="+")
    last_seen_scan = models.ForeignKey(Scan, on_delete=models.RESTRICT, related_name="+")
    first_seen_at = models.DateTimeField()
    last_seen_at = models.DateTimeField()
    fixed_at = models.DateTimeField(null=True, blank=True)
    reopened_count = models.PositiveIntegerField(default=0)
    accepted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL, null=True, blank=True, on_delete=models.SET_NULL, related_name="+"
    )
    accepted_reason = models.TextField(blank=True)
    accepted_until = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "findings"
        constraints = [
            models.UniqueConstraint(
                fields=["domain", "fingerprint"], name="findings_domain_fp_uniq"
            ),
            models.UniqueConstraint(fields=["id", "tenant"], name="findings_id_tenant_uniq"),
            models.CheckConstraint(
                condition=Q(score__gte=0, score__lte=10), name="findings_score_range"
            ),
            models.CheckConstraint(
                condition=Q(
                    exploitability__gte=0, exploitability__lte=1, exposure__gte=0, exposure__lte=1
                ),
                name="findings_factors_range",
            ),
            models.CheckConstraint(
                condition=~Q(status="accepted_risk") | ~Q(accepted_reason=""),
                name="findings_accepted_needs_reason",
            ),
        ]
        indexes = [
            models.Index(fields=["tenant", "status", "-score"], name="findings_open_ranked_idx"),
            models.Index(fields=["domain", "status"], name="findings_domain_status_idx"),
        ]


class FindingObservation(TenantOwnedModel):
    """Evidence from one scan. Records which library text and scoring model produced it."""

    finding = models.ForeignKey(Finding, on_delete=models.CASCADE)
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE)
    check_definition = models.ForeignKey(CheckDefinition, on_delete=models.PROTECT)
    scoring_model = models.ForeignKey(ScoringModel, on_delete=models.PROTECT)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES)
    exploitability = models.DecimalField(max_digits=3, decimal_places=2)
    exposure = models.DecimalField(max_digits=3, decimal_places=2)
    score = models.DecimalField(max_digits=4, decimal_places=2)
    evidence = models.JSONField(default=dict, blank=True)
    observed_at = models.DateTimeField()

    class Meta:
        db_table = "finding_observations"
        constraints = [
            models.UniqueConstraint(
                fields=["finding", "scan"], name="observations_finding_scan_uniq"
            ),
        ]
        indexes = [models.Index(fields=["scan"], name="observations_scan_idx")]