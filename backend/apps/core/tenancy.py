"""Database tenant context.

Row-level security policies read two transaction-local settings:
    app.current_tenant  -> which organisation's rows are visible
    app.current_user    -> lets a user read their own memberships before a tenant is chosen

They are set with set_config(..., is_local => true), so they vanish when the transaction ends.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from uuid import UUID

from django.db import connection, transaction


def _set_local(name: str, value: str) -> None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT set_config(%s, %s, true)", [name, value])


def activate(*, user_id: UUID | None = None, tenant_id: UUID | None = None) -> None:
    """Set the DB context. Must run inside a transaction (ATOMIC_REQUESTS provides one)."""
    if not connection.in_atomic_block:
        raise RuntimeError("tenant context requires an open transaction")
    if user_id is not None:
        _set_local("app.current_user", str(user_id))
    if tenant_id is not None:
        _set_local("app.current_tenant", str(tenant_id))


@contextmanager
def tenant_context(tenant_id: UUID, user_id: UUID | None = None) -> Iterator[None]:
    """For code outside HTTP requests (Celery tasks, management commands)."""
    with transaction.atomic():
        activate(user_id=user_id, tenant_id=tenant_id)
        yield
