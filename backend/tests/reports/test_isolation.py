"""Tenant isolation for reports is enforced by PostgreSQL, not only by application code."""

import pytest
from django.db import IntegrityError, connection, transaction

from apps.findings import selectors as finding_selectors
from apps.reports import services
from apps.reports.models import Report

pytestmark = pytest.mark.usefixtures("library")


def _set(name, value):
    with connection.cursor() as cur:
        cur.execute("SELECT set_config(%s, %s, true)", [name, str(value)])


def _count():
    with connection.cursor() as cur:
        cur.execute("SELECT count(*) FROM reports")
        return cur.fetchone()[0]


def test_each_organisation_sees_only_its_own_reports(
    scanned_domain, tenant_a, tenant_b, app_api_role
):
    services.generate_report(domain=scanned_domain)
    app_api_role()

    assert _count() == 0  # no tenant chosen: fail closed
    _set("app.current_tenant", tenant_b.id)
    assert _count() == 0
    _set("app.current_tenant", tenant_a.id)
    assert _count() == 1


def test_a_report_cannot_point_at_another_organisations_domain(scanned_domain, tenant_b):
    report = services.generate_report(domain=scanned_domain)
    with pytest.raises(IntegrityError), transaction.atomic():
        Report.objects.create(
            tenant=tenant_b,  # wrong organisation for this domain and scan
            domain=scanned_domain,
            scan=report.scan,
            scoring_model=finding_selectors.current_scoring_model(),
            score=50,
            grade="F",
            open_findings=0,
            snapshot_version=1,
            snapshot={},
            content_sha256="0" * 64,
        )