import pytest
from django.db import connection
from rest_framework.test import APIClient

from apps.accounts.models import Tenant
from apps.core.models import AuditLog
from apps.domains.models import Domain


def client_for(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


@pytest.fixture
def domain(tenant_a):
    return Domain.objects.create(tenant=tenant_a, fqdn="acme.example")


def test_passive_scan_can_be_requested_and_listed(user_a, domain):
    client = client_for(user_a)
    created = client.post(f"/api/v1/domains/{domain.id}/scans/", {"mode": "passive"}, format="json")
    assert created.status_code == 201
    assert created.json()["status"] == "queued"
    listed = client.get(f"/api/v1/domains/{domain.id}/scans/").json()
    assert [s["id"] for s in listed] == [created.json()["id"]]
    assert client.get(f"/api/v1/scans/{created.json()['id']}/").status_code == 200


def test_mode_defaults_to_passive(user_a, domain):
    response = client_for(user_a).post(f"/api/v1/domains/{domain.id}/scans/", {}, format="json")
    assert response.json()["mode"] == "passive"


def test_invalid_mode_is_rejected(user_a, domain):
    response = client_for(user_a).post(
        f"/api/v1/domains/{domain.id}/scans/", {"mode": "nuke"}, format="json"
    )
    assert response.status_code == 400


def test_active_scan_on_free_plan_is_forbidden(user_a, domain):
    response = client_for(user_a).post(
        f"/api/v1/domains/{domain.id}/scans/", {"mode": "active"}, format="json"
    )
    assert response.status_code == 403
    assert response.json()["detail"]


def test_active_scan_on_unverified_domain_is_a_conflict(user_a, tenant_a, domain):
    tenant_a.plan = Tenant.Plan.STARTER
    tenant_a.save()
    response = client_for(user_a).post(
        f"/api/v1/domains/{domain.id}/scans/", {"mode": "active"}, format="json"
    )
    assert response.status_code == 409


def test_refusals_are_audited_with_request_details(user_a, tenant_a, domain):
    tenant_a.plan = Tenant.Plan.STARTER
    tenant_a.save()
    client_for(user_a).post(
        f"/api/v1/domains/{domain.id}/scans/", {"mode": "active"}, format="json"
    )
    event = AuditLog.objects.get(action="scan.refused", target_id=domain.id)
    assert event.actor_id == user_a.id
    assert event.metadata == {"reason": "domain_not_verified", "mode": "active"}
    assert event.ip == "127.0.0.1"


def test_quota_exhaustion_returns_429(user_a, domain):
    client = client_for(user_a)
    for _ in range(3):
        assert (
            client.post(f"/api/v1/domains/{domain.id}/scans/", {}, format="json").status_code == 201
        )
    assert client.post(f"/api/v1/domains/{domain.id}/scans/", {}, format="json").status_code == 429


def test_other_tenants_scans_are_invisible_under_rls(
    user_a, user_b, tenant_a, tenant_b, domain, app_api_role
):
    other = Domain.objects.create(tenant=tenant_b, fqdn="globex.example")
    mine = client_for(user_a).post(f"/api/v1/domains/{domain.id}/scans/", {}, format="json").json()
    theirs = client_for(user_b).post(f"/api/v1/domains/{other.id}/scans/", {}, format="json").json()
    app_api_role()

    assert client_for(user_a).get(f"/api/v1/scans/{mine['id']}/").status_code == 200
    assert client_for(user_a).get(f"/api/v1/scans/{theirs['id']}/").status_code == 404
    assert client_for(user_a).get(f"/api/v1/domains/{other.id}/scans/").status_code == 404
    assert (
        client_for(user_a).post(f"/api/v1/domains/{other.id}/scans/", {}, format="json").status_code
        == 404
    )


def test_scan_request_works_for_the_restricted_role(user_a, domain, app_api_role):
    app_api_role()
    response = client_for(user_a).post(f"/api/v1/domains/{domain.id}/scans/", {}, format="json")
    assert response.status_code == 201
    with connection.cursor() as cur:  # the audit write also succeeded under RLS
        cur.execute("SELECT set_config('app.current_tenant', %s, true)", [str(domain.tenant_id)])
        cur.execute("SELECT count(*) FROM audit_log WHERE action = 'scan.requested'")
        assert cur.fetchone()[0] == 1