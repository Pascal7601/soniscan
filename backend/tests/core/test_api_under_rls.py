"""End-to-end: the real API running as the restricted `app_api` role, so RLS is genuinely active.

Other API tests run as a superuser (which bypasses RLS). These prove that TenantScopedAPIView
and the policies work together, and that a request can never see another tenant's data.
"""

import pytest
from django.db import connection
from rest_framework.test import APIClient

from apps.accounts.models import Membership, Tenant
from apps.domains.models import Domain


@pytest.fixture
def as_app_api(db):
    """Run everything after this fixture as the non-superuser role."""
    with connection.cursor() as cur:
        cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'app_api'")
        if cur.fetchone() is None:
            pytest.skip("app_api role missing; run infra/postgres/init.sql")
        cur.execute(
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO app_api"
        )


def _client(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


def test_user_only_sees_their_own_tenants_domains(user_a, user_b, tenant_a, tenant_b, as_app_api):
    # Seed as superuser (still before switching role), one domain per tenant.
    Domain.objects.create(tenant=tenant_a, fqdn="acme.example")
    Domain.objects.create(tenant=tenant_b, fqdn="globex.example")
    with connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE app_api")

    seen_a = [d["fqdn"] for d in _client(user_a).get("/api/v1/domains/").json()]
    seen_b = [d["fqdn"] for d in _client(user_b).get("/api/v1/domains/").json()]
    assert seen_a == ["acme.example"]
    assert seen_b == ["globex.example"]


def test_full_flow_works_for_the_restricted_role(user_a, as_app_api):
    with connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE app_api")
    client = _client(user_a)

    assert client.get("/api/v1/me/").json()["memberships"][0]["role"] == "owner"
    created = client.post("/api/v1/domains/", {"fqdn": "acme.example"}, format="json")
    assert created.status_code == 201
    started = client.post(f"/api/v1/domains/{created.json()['id']}/verification/")
    assert started.status_code == 201


def test_cannot_reach_another_tenants_domain_by_id(user_a, tenant_b, as_app_api):
    other = Domain.objects.create(tenant=tenant_b, fqdn="globex.example")
    with connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE app_api")
    response = _client(user_a).post(f"/api/v1/domains/{other.id}/verification/")
    assert response.status_code == 404


def test_spoofed_tenant_header_is_rejected(user_a, tenant_b, as_app_api):
    with connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE app_api")
    response = _client(user_a).get("/api/v1/domains/", headers={"X-Tenant-ID": str(tenant_b.id)})
    assert response.status_code == 403


def test_new_organisation_flow_under_rls(db, as_app_api):
    from apps.accounts.models import User
    from apps.accounts.services import create_tenant_with_owner

    owner = User.objects.create_user(email="new@owner.example", password="x" * 14)
    with connection.cursor() as cur:
        cur.execute("SET LOCAL ROLE app_api")
    tenant = create_tenant_with_owner(owner=owner, name="Fresh Co")
    assert Tenant.objects.filter(id=tenant.id).exists()
    assert Membership.objects.filter(tenant=tenant, user=owner, role="owner").exists()
