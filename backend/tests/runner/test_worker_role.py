"""The scanner worker runs as its own least-privilege database role. These tests switch to that
role using only the grants the runner migration gave it, proving the grants are enough for real
work and no more."""

from datetime import timedelta

import pytest
from django.db import ProgrammingError, connection
from django.utils import timezone

from apps.core.tenancy import tenant_context
from apps.domains.models import Domain
from apps.findings.models import Finding
from apps.runner import services
from apps.runner.services import ExecutionResult
from apps.scans.models import Scan

from .conftest import FakeResolver

pytestmark = pytest.mark.usefixtures("library")


def test_a_full_scan_runs_with_only_the_worker_grants(queued_scan, worker_role):
    worker_role()
    result = services.execute_scan(
        tenant_id=queued_scan.tenant_id, scan_id=queued_scan.id, resolver=FakeResolver()
    )
    assert result == ExecutionResult.SUCCEEDED
    connection.cursor().execute("RESET ROLE")
    assert Finding.objects.count() == 1


def test_the_reaper_finds_stuck_scans_of_every_tenant_and_fails_them(domain, tenant_b, worker_role):
    other = Domain.objects.create(tenant=tenant_b, fqdn="globex.example")
    old = timezone.now() - timedelta(hours=1)
    mine = Scan.objects.create(
        tenant_id=domain.tenant_id, domain=domain, mode="passive", trigger_type="manual",
        status=Scan.Status.RUNNING, started_at=old,
    )  # fmt: skip
    theirs = Scan.objects.create(
        tenant_id=other.tenant_id, domain=other, mode="passive", trigger_type="manual",
        status=Scan.Status.RUNNING, started_at=old,
    )  # fmt: skip

    worker_role()
    assert services.reap_stale_scans() == 2

    connection.cursor().execute("RESET ROLE")
    statuses = Scan.objects.filter(id__in=[mine.id, theirs.id]).values_list("status", flat=True)
    assert set(statuses) == {Scan.Status.FAILED}


def test_without_a_tenant_the_worker_sees_only_unfinished_scans(domain, worker_role):
    for status in (Scan.Status.SUCCEEDED, Scan.Status.FAILED, Scan.Status.RUNNING):
        Scan.objects.create(
            tenant_id=domain.tenant_id, domain=domain, mode="passive",
            trigger_type="manual", status=status,
        )  # fmt: skip
    worker_role()
    with connection.cursor() as cur:
        cur.execute("SELECT status FROM scans")
        assert [row[0] for row in cur.fetchall()] == ["running"]
        cur.execute("SELECT count(*) FROM domains")
        assert cur.fetchone()[0] == 0  # no tenant context, no tenant data
        cur.execute("SELECT count(*) FROM findings")
        assert cur.fetchone()[0] == 0


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT count(*) FROM memberships",
        "SELECT count(*) FROM users",
        "SELECT count(*) FROM tenants",
        "UPDATE check_definitions SET title = 'tampered'",
        "UPDATE scoring_models SET params = '{}'::jsonb",
        "DELETE FROM findings",
        "DELETE FROM scans",
        "DELETE FROM audit_log",
        "INSERT INTO domains (id, tenant_id, fqdn, status, created_at, updated_at) "
        "VALUES (gen_random_uuid(), gen_random_uuid(), 'x.example', 'pending', now(), now())",
    ],
)
def test_the_worker_cannot_reach_what_it_does_not_need(domain, worker_role, sql):
    worker_role()
    with connection.cursor() as cur, pytest.raises(ProgrammingError, match="permission denied"):
        cur.execute(sql)


@pytest.mark.parametrize(
    "sql",
    [
        "UPDATE scans SET mode = 'active'",  # turning a passive scan into an active one
        "UPDATE scans SET tenant_id = gen_random_uuid()",
        "UPDATE domains SET fqdn = 'evil.example'",
        "UPDATE domains SET tenant_id = gen_random_uuid()",
    ],
)
def test_the_worker_cannot_change_what_a_scan_or_domain_is(queued_scan, worker_role, sql):
    worker_role()
    # pytest.raises goes OUTERMOST so the error unwinds through tenant_context's savepoint first.
    with (
        pytest.raises(ProgrammingError, match="permission denied"),
        tenant_context(queued_scan.tenant_id),
        connection.cursor() as cur,
    ):
        cur.execute(sql)