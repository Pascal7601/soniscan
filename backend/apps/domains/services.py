"""Domain business rules: validation, quotas, ownership verification."""

import hashlib
import hmac
import ipaddress
import re
import secrets
from collections.abc import Iterable
from datetime import datetime, timedelta
from uuid import UUID
from publicsuffixlist import PublicSuffixList

from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.accounts.models import Tenant

from .models import Domain, DomainVerification

TXT_PREFIX = "posture-verify="
VERIFICATION_TTL = timedelta(days=7)
REVERIFY_AFTER = timedelta(days=90)
PLAN_MAX_DOMAINS = {"free": 1, "starter": 3, "business": 10}

_LABEL = r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
_FQDN_RE = re.compile(rf"^{_LABEL}(\.{_LABEL})+$")

psl = PublicSuffixList()

class DomainError(Exception):
    """Base class for domain rule violations (mapped to HTTP 400/409 at the API layer)."""


class InvalidDomain(DomainError):
    pass


class QuotaExceeded(DomainError):
    pass


class DomainAlreadyClaimed(DomainError):
    pass


def normalise_fqdn(raw: str) -> str:
    value = raw.strip().lower().rstrip(".")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise InvalidDomain("Enter a domain name, not an IP address.")
    try:
        value = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidDomain("Invalid domain name.") from exc
    if len(value) > 253 or not _FQDN_RE.match(value):
        raise InvalidDomain("Invalid domain name.")
    if psl.ispublicsuffix(value):
        raise InvalidDomain("You cannot scan a public suffix. Please provide a specific subdomain.")
    return value


@transaction.atomic
def add_domain(*, tenant_id: UUID, fqdn: str) -> Domain:
    tenant = Tenant.objects.select_for_update().get(id=tenant_id)
    limit = PLAN_MAX_DOMAINS[tenant.plan]
    if Domain.objects.filter(tenant_id=tenant_id).count() >= limit:
        raise QuotaExceeded(f"Your plan allows {limit} domain(s).")
    try:
        with transaction.atomic():
            return Domain.objects.create(tenant_id=tenant_id, fqdn=normalise_fqdn(fqdn))
    except IntegrityError as exc:
        raise InvalidDomain("This domain is already in your account.") from exc


def verification_record_name(domain: Domain) -> str:
    return f"_posture-verify.{domain.fqdn}"


def _hash(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def start_verification(
    *, domain: Domain, method: str = Domain.Method.DNS_TXT
) -> tuple[DomainVerification, str]:
    """Create a verification attempt. Returns (record, plaintext_token); token is shown once."""
    token = secrets.token_urlsafe(32)
    verification = DomainVerification.objects.create(
        tenant_id=domain.tenant_id,
        domain=domain,
        method=method,
        token_hash=_hash(token),
        expires_at=timezone.now() + VERIFICATION_TTL,
    )
    return verification, token


@transaction.atomic
def complete_verification(
    *, verification: DomainVerification, observed_values: Iterable[str], now: datetime | None = None
) -> bool:
    """Check observed DNS TXT (or file) values against the stored hash. Pure of network access."""
    now = now or timezone.now()
    if verification.result != DomainVerification.Result.PENDING:
        return False
    if verification.expires_at <= now:
        verification.result = DomainVerification.Result.EXPIRED
        verification.save(update_fields=["result", "updated_at"])
        return False

    expected = bytes(verification.token_hash)
    matched = any(
        hmac.compare_digest(_hash(value.removeprefix(TXT_PREFIX).strip()), expected)
        for value in observed_values
        if value.startswith(TXT_PREFIX)
    )
    verification.checked_at = now
    if not matched:
        verification.result = DomainVerification.Result.FAILED
        verification.save(update_fields=["result", "checked_at", "updated_at"])
        return False

    domain = verification.domain
    domain.status = Domain.Status.VERIFIED
    domain.verified_at = now
    domain.verified_method = verification.method
    domain.reverify_due = now + REVERIFY_AFTER
    try:
        with transaction.atomic():
            domain.save()
    except IntegrityError as exc:
        raise DomainAlreadyClaimed("Another organisation has verified this domain.") from exc
    verification.result = DomainVerification.Result.VERIFIED
    verification.save(update_fields=["result", "checked_at", "updated_at"])
    return True
