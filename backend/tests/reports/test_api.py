import pytest
from rest_framework.test import APIClient

from apps.accounts.models import Membership, User
from apps.core.models import AuditLog
from apps.reports import services
from apps.reports.models import Report

pytestmark = pytest.mark.usefixtures("library")


def client_for(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


@pytest.fixture
def viewer(tenant_a):
    user = User.objects.create_user(email="v@acme.example", password="x" * 14)
    Membership.objects.create(tenant=tenant_a, user=user, role=Membership.Role.VIEWER)
    return user


def url(domain):
    return f"/api/v1/domains/{domain.id}/reports/"


def test_an_owner_generates_lists_and_reads_a_report(user_a, scanned_domain):
    client = client_for(user_a)
    created = client.post(url(scanned_domain))
    assert created.status_code == 201
    body = created.json()
    assert (body["score"], body["grade"], body["open_findings"]) == (69, "D", 2)
    assert "snapshot" not in body

    assert [r["id"] for r in client.get(url(scanned_domain)).json()] == [body["id"]]
    assert client.get(f"/api/v1/reports/{body['id']}/").json()["id"] == body["id"]


def test_the_pdf_downloads_as_an_attachment(user_a, scanned_domain):
    client = client_for(user_a)
    report_id = client.post(url(scanned_domain)).json()["id"]

    response = client.get(f"/api/v1/reports/{report_id}/pdf/")

    assert response.status_code == 200
    assert response["Content-Type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-")
    assert response["Content-Disposition"].startswith("attachment;")
    assert "acme.example" in response["Content-Disposition"]
    assert "no-store" in response["Cache-Control"]
    row = AuditLog.objects.get(action="report.downloaded")
    assert str(row.target_id) == report_id and row.ip


def test_a_viewer_can_read_and_download_but_not_generate(user_a, viewer, scanned_domain):
    report_id = client_for(user_a).post(url(scanned_domain)).json()["id"]
    client = client_for(viewer)

    assert client.post(url(scanned_domain)).status_code == 403
    assert client.get(url(scanned_domain)).status_code == 200
    assert client.get(f"/api/v1/reports/{report_id}/pdf/").status_code == 200


def test_no_scan_yet_is_a_conflict(user_a, domain):
    response = client_for(user_a).post(url(domain))
    assert response.status_code == 409
    assert response.json()["code"] == "no_completed_scan"


def test_another_organisation_cannot_see_the_report(user_a, user_b, scanned_domain):
    report_id = client_for(user_a).post(url(scanned_domain)).json()["id"]
    other = client_for(user_b)

    assert other.get(f"/api/v1/reports/{report_id}/").status_code == 404
    assert other.get(f"/api/v1/reports/{report_id}/pdf/").status_code == 404
    assert other.get(url(scanned_domain)).status_code == 404
    assert other.post(url(scanned_domain)).status_code == 404


def test_a_report_that_no_longer_matches_its_hash_is_not_served(user_a, scanned_domain, db):
    from django.db import connection

    report = services.generate_report(domain=scanned_domain, actor_id=user_a.id)
    with connection.cursor() as cur:  # bypass the ORM; the trigger blocks UPDATE, so pause it
        cur.execute("ALTER TABLE reports DISABLE TRIGGER reports_no_update")
        cur.execute("UPDATE reports SET snapshot = %s::jsonb WHERE id = %s", ["{}", report.id])
        cur.execute("ALTER TABLE reports ENABLE TRIGGER reports_no_update")
    response = client_for(user_a).get(f"/api/v1/reports/{report.id}/pdf/")
    assert response.status_code == 500
    assert response.json()["code"] == "report_integrity"
    assert Report.objects.filter(id=report.id).exists()