import pytest
from django.db import DatabaseError, connection, transaction

from apps.core import audit
from apps.core.models import AuditLog


def test_record_writes_an_event(tenant_a):
    audit.record(
        action="test.event",
        tenant_id=tenant_a.id,
        target_type="thing",
        metadata={"k": "v"},
        ip="203.0.113.9",
        user_agent="pytest",
    )
    row = AuditLog.objects.get(action="test.event")
    assert row.tenant_id == tenant_a.id
    assert row.metadata == {"k": "v"}
    assert row.ip == "203.0.113.9"


def test_audit_log_cannot_be_updated(tenant_a):
    audit.record(action="test.event", tenant_id=tenant_a.id)
    with pytest.raises(DatabaseError, match="append-only"), transaction.atomic():
        AuditLog.objects.update(action="tampered")


def test_audit_log_cannot_be_deleted(tenant_a):
    audit.record(action="test.event", tenant_id=tenant_a.id)
    with pytest.raises(DatabaseError, match="append-only"), transaction.atomic():
        AuditLog.objects.all().delete()


def test_audit_log_cannot_be_truncated(db):
    with (
        pytest.raises(DatabaseError, match="append-only"),
        transaction.atomic(),
        connection.cursor() as cur,
    ):
        cur.execute("TRUNCATE audit_log")


def test_system_events_without_tenant_work_under_the_restricted_role(app_api_role):
    app_api_role()
    audit.record(action="system.startup", actor_type="system")  # tenant_id NULL, no context set


def test_tenants_read_only_their_own_events(tenant_a, tenant_b, app_api_role):
    audit.record(action="a.event", tenant_id=tenant_a.id)
    audit.record(action="b.event", tenant_id=tenant_b.id)
    audit.record(action="system.event", actor_type="system")
    app_api_role()
    with connection.cursor() as cur:
        cur.execute("SELECT set_config('app.current_tenant', %s, true)", [str(tenant_a.id)])
        cur.execute("SELECT action FROM audit_log ORDER BY action")
        assert [r[0] for r in cur.fetchall()] == ["a.event"]