from django.db import models
from django.db.models import Q
from django.db.models.functions import Lower

from apps.core.models import TenantOwnedModel


class Domain(TenantOwnedModel):
    class Status(models.TextChoices):
        PENDING = "pending"
        VERIFIED = "verified"
        EXPIRED = "expired"
        SUSPENDED = "suspended"

    class Method(models.TextChoices):
        DNS_TXT = "dns_txt"
        HTTP_FILE = "http_file"

    fqdn = models.CharField(max_length=253)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    verified_at = models.DateTimeField(null=True, blank=True)
    verified_method = models.CharField(
        max_length=20, choices=Method.choices, blank=True, default=""
    )
    reverify_due = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "domains"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "fqdn"], name="domains_tenant_fqdn_uniq"),
            # Target of composite foreign keys from child tables (tenant-consistency guarantee).
            models.UniqueConstraint(fields=["id", "tenant"], name="domains_id_tenant_uniq"),
            # Only one organisation can hold a verified claim on a domain at a time.
            models.UniqueConstraint(
                fields=["fqdn"],
                condition=Q(status="verified"),
                name="domains_single_verified_owner",
            ),
            models.CheckConstraint(condition=Q(fqdn=Lower("fqdn")), name="domains_fqdn_lowercase"),
            models.CheckConstraint(
                condition=~Q(status="verified")
                | Q(
                    verified_at__isnull=False,
                    verified_method__gt="",
                    reverify_due__isnull=False,
                ),
                name="domains_verified_fields_set",
            ),
        ]

    def __str__(self) -> str:
        return self.fqdn


class DomainVerification(TenantOwnedModel):
    class Result(models.TextChoices):
        PENDING = "pending"
        VERIFIED = "verified"
        FAILED = "failed"
        EXPIRED = "expired"

    domain = models.ForeignKey(Domain, on_delete=models.CASCADE, related_name="verifications")
    method = models.CharField(max_length=20, choices=Domain.Method.choices)
    token_hash = models.BinaryField()  # SHA-256 of the token; plaintext is shown once
    expires_at = models.DateTimeField()
    checked_at = models.DateTimeField(null=True, blank=True)
    result = models.CharField(max_length=20, choices=Result.choices, default=Result.PENDING)

    class Meta:
        db_table = "domain_verifications"
