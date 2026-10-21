from datetime import timedelta

import pytest
from django.utils import timezone

from apps.accounts.models import Tenant
from apps.domains import services
from apps.domains.models import Domain, DomainVerification


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        (" example.com. ", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
    ],
)
def test_normalise_accepts_and_cleans(raw, expected):
    assert services.normalise_fqdn(raw) == expected


@pytest.mark.parametrize(
    "raw", ["localhost", "192.168.1.1", "-bad.example", "a b.example", "", "x" * 300 + ".com"]
)
def test_normalise_rejects(raw):
    with pytest.raises(services.InvalidDomain):
        services.normalise_fqdn(raw)


def test_plan_quota_is_enforced(tenant_a):
    services.add_domain(tenant_id=tenant_a.id, fqdn="one.example")
    with pytest.raises(services.QuotaExceeded):
        services.add_domain(tenant_id=tenant_a.id, fqdn="two.example")


def test_duplicate_domain_in_same_tenant(tenant_a):
    tenant_a.plan = Tenant.Plan.BUSINESS
    tenant_a.save()
    services.add_domain(tenant_id=tenant_a.id, fqdn="one.example")
    with pytest.raises(services.InvalidDomain):
        services.add_domain(tenant_id=tenant_a.id, fqdn="ONE.example")


def test_token_is_stored_hashed_never_in_plaintext(tenant_a):
    domain = services.add_domain(tenant_id=tenant_a.id, fqdn="one.example")
    verification, token = services.start_verification(domain=domain)
    assert token.encode() not in bytes(verification.token_hash)
    assert len(bytes(verification.token_hash)) == 32


def test_verification_succeeds_with_correct_token(tenant_a):
    domain = services.add_domain(tenant_id=tenant_a.id, fqdn="one.example")
    verification, token = services.start_verification(domain=domain)
    assert services.complete_verification(
        verification=verification, observed_values=["unrelated", f"{services.TXT_PREFIX}{token}"]
    )
    domain.refresh_from_db()
    assert domain.status == Domain.Status.VERIFIED
    assert domain.reverify_due > timezone.now() + timedelta(days=80)


def test_verification_fails_with_wrong_token(tenant_a):
    domain = services.add_domain(tenant_id=tenant_a.id, fqdn="one.example")
    verification, _ = services.start_verification(domain=domain)
    assert not services.complete_verification(
        verification=verification, observed_values=[f"{services.TXT_PREFIX}wrong"]
    )
    domain.refresh_from_db()
    assert domain.status == Domain.Status.PENDING


def test_expired_verification_is_rejected(tenant_a):
    domain = services.add_domain(tenant_id=tenant_a.id, fqdn="one.example")
    verification, token = services.start_verification(domain=domain)
    later = timezone.now() + services.VERIFICATION_TTL + timedelta(seconds=1)
    assert not services.complete_verification(
        verification=verification, observed_values=[f"{services.TXT_PREFIX}{token}"], now=later
    )
    verification.refresh_from_db()
    assert verification.result == DomainVerification.Result.EXPIRED


def test_second_tenant_cannot_verify_an_already_verified_domain(tenant_a, tenant_b):
    d_a = services.add_domain(tenant_id=tenant_a.id, fqdn="shared.example")
    v_a, t_a = services.start_verification(domain=d_a)
    assert services.complete_verification(
        verification=v_a, observed_values=[f"{services.TXT_PREFIX}{t_a}"]
    )

    d_b = services.add_domain(tenant_id=tenant_b.id, fqdn="shared.example")
    v_b, t_b = services.start_verification(domain=d_b)
    with pytest.raises(services.DomainAlreadyClaimed):
        services.complete_verification(
            verification=v_b, observed_values=[f"{services.TXT_PREFIX}{t_b}"]
        )
