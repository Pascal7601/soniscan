import pytest
from rest_framework.test import APIClient

from apps.accounts.models import Membership, Tenant


def client_for(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


def test_me_requires_authentication(db):
    assert APIClient().get("/api/v1/me/").status_code in (401, 403)


def test_me_returns_memberships(user_a, tenant_a):
    response = client_for(user_a).get("/api/v1/me/")
    assert response.status_code == 200
    assert response.json()["memberships"][0]["tenant_id"] == str(tenant_a.id)


def test_single_membership_needs_no_header(user_a):
    assert client_for(user_a).get("/api/v1/domains/").status_code == 200


def test_header_required_with_multiple_memberships(user_a):
    other = Tenant.objects.create(name="Second")
    Membership.objects.create(tenant=other, user=user_a, role=Membership.Role.VIEWER)
    assert client_for(user_a).get("/api/v1/domains/").status_code == 400


def test_cannot_act_for_an_organisation_you_do_not_belong_to(user_a, tenant_b):
    response = client_for(user_a).get("/api/v1/domains/", headers={"X-Tenant-ID": str(tenant_b.id)})
    assert response.status_code == 403


def test_bad_tenant_header_is_a_client_error(user_a):
    assert (
        client_for(user_a).get("/api/v1/domains/", headers={"X-Tenant-ID": "nope"}).status_code
        == 400
    )


@pytest.mark.parametrize("fqdn", ["127.0.0.1", "localhost"])
def test_create_domain_rejects_invalid_input(user_a, fqdn):
    response = client_for(user_a).post("/api/v1/domains/", {"fqdn": fqdn}, format="json")
    assert response.status_code == 400


def test_domain_create_list_and_verification_flow(user_a):
    client = client_for(user_a)
    created = client.post("/api/v1/domains/", {"fqdn": "Acme.Example"}, format="json")
    assert created.status_code == 201
    assert created.json()["fqdn"] == "acme.example"
    assert [d["fqdn"] for d in client.get("/api/v1/domains/").json()] == ["acme.example"]

    started = client.post(f"/api/v1/domains/{created.json()['id']}/verification/")
    assert started.status_code == 201
    body = started.json()
    assert body["record_name"] == "_posture-verify.acme.example"
    assert body["record_value"].startswith("posture-verify=")
