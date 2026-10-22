import pytest

from apps.accounts.models import Membership, Tenant, User


@pytest.fixture
def tenant_a(db) -> Tenant:
    return Tenant.objects.create(name="Acme Ltd")


@pytest.fixture
def tenant_b(db) -> Tenant:
    return Tenant.objects.create(name="Globex Ltd")


@pytest.fixture
def user_a(tenant_a) -> User:
    user = User.objects.create_user(email="a@acme.example", password="x" * 14)
    Membership.objects.create(tenant=tenant_a, user=user, role=Membership.Role.OWNER)
    return user


@pytest.fixture
def user_b(tenant_b) -> User:
    user = User.objects.create_user(email="b@globex.example", password="x" * 14)
    Membership.objects.create(tenant=tenant_b, user=user, role=Membership.Role.OWNER)
    return user


@pytest.fixture
def app_api_role(db):
    """Returns a function that switches the current transaction to the restricted `app_api` role.

    Superusers bypass row-level security, so tests that must prove isolation call this AFTER
    seeding data. Skips if the role does not exist (see infra/postgres/init.sql).
    """
    from django.db import connection

    def switch() -> None:
        with connection.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'app_api'")
            if cur.fetchone() is None:
                pytest.skip("app_api role missing; run infra/postgres/init.sql")
            cur.execute(
                "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_api"
            )
            cur.execute("SET LOCAL ROLE app_api")

    return switch


@pytest.fixture
def verified_domain(tenant_a):
    from datetime import timedelta

    from django.utils import timezone

    from apps.domains.models import Domain

    return Domain.objects.create(
        tenant=tenant_a,
        fqdn="acme.example",
        status=Domain.Status.VERIFIED,
        verified_at=timezone.now(),
        verified_method=Domain.Method.DNS_TXT,
        reverify_due=timezone.now() + timedelta(days=90),
    )