"""The security-critical tests: prove isolation is enforced by the DATABASE, not just app code.

These switch to the non-superuser `app_api` role (created by infra/postgres/init.sql) because
superusers bypass row-level security. They skip if that role does not exist.
"""

import pytest
from django.db import IntegrityError, connection, transaction

from apps.accounts.models import Membership
from apps.domains.models import Domain, DomainVerification


def _use_app_api_role():
    with connection.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'app_api'")
        if cur.fetchone() is None:
            pytest.skip("app_api role missing; run infra/postgres/init.sql")
        cur.execute(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_api"
        )
        cur.execute("SET LOCAL ROLE app_api")


def _set(name, value):
    with connection.cursor() as cur:
        cur.execute("SELECT set_config(%s, %s, true)", [name, str(value)])


def _count(table):
    with connection.cursor() as cur:
        cur.execute(f"SELECT count(*) FROM {table}")  # noqa: S608
        return cur.fetchone()[0]


@pytest.fixture
def two_tenants_with_domains(tenant_a, tenant_b, user_a, user_b):
    Domain.objects.create(tenant=tenant_a, fqdn="a.example")
    Domain.objects.create(tenant=tenant_b, fqdn="b.example")


def test_no_tenant_context_sees_nothing(two_tenants_with_domains):
    _use_app_api_role()
    assert _count("domains") == 0


def test_each_tenant_sees_only_its_own_rows(two_tenants_with_domains, tenant_a, tenant_b):
    _use_app_api_role()
    _set("app.current_tenant", tenant_a.id)
    assert _count("domains") == 1
    _set("app.current_tenant", tenant_b.id)
    assert _count("domains") == 1
    with connection.cursor() as cur:
        cur.execute("SELECT fqdn FROM domains")
        assert cur.fetchone()[0] == "b.example"


def test_cannot_write_rows_for_another_tenant(two_tenants_with_domains, tenant_a, tenant_b):
    _use_app_api_role()
    _set("app.current_tenant", tenant_a.id)
    with pytest.raises(Exception, match="row-level security"), transaction.atomic():
        Domain.objects.create(tenant=tenant_b, fqdn="sneaky.example")


def test_user_sees_own_memberships_before_choosing_a_tenant(two_tenants_with_domains, user_a):
    _use_app_api_role()
    assert _count("memberships") == 0
    _set("app.current_user", user_a.id)
    assert _count("memberships") == 1


def test_child_row_cannot_reference_another_tenants_parent(tenant_a, tenant_b):
    domain_a = Domain.objects.create(tenant=tenant_a, fqdn="a.example")
    with pytest.raises(IntegrityError), transaction.atomic():
        DomainVerification.objects.create(
            tenant=tenant_b,
            domain=domain_a,
            method="dns_txt",
            token_hash=b"x" * 32,
            expires_at="2030-01-01T00:00:00Z",
        )


def test_only_one_tenant_can_hold_a_verified_claim(tenant_a, tenant_b):
    kwargs = {
        "status": "verified",
        "verified_at": "2026-01-01T00:00:00Z",
        "verified_method": "dns_txt",
        "reverify_due": "2026-04-01T00:00:00Z",
    }
    Domain.objects.create(tenant=tenant_a, fqdn="x.example", **kwargs)
    with pytest.raises(IntegrityError), transaction.atomic():
        Domain.objects.create(tenant=tenant_b, fqdn="x.example", **kwargs)


def test_membership_unique_per_user_and_tenant(user_a, tenant_a):
    with pytest.raises(IntegrityError), transaction.atomic():
        Membership.objects.create(tenant=tenant_a, user=user_a, role="viewer")
