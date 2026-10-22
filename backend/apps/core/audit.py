"""Audit trail. Call record() for every security-relevant event.

Uses a plain INSERT (no RETURNING): with row-level security, RETURNING would require the new row
to also pass the SELECT policy, which system events (tenant_id NULL) deliberately do not.
"""

import json
from typing import Any
from uuid import UUID

from django.db import connection
from django.http import HttpRequest
from django.utils import timezone

_INSERT = """
    INSERT INTO audit_log
      (occurred_at, tenant_id, actor_type, actor_id, action, target_type, target_id,
       ip, user_agent, metadata)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s::inet, %s, %s::jsonb)
"""


def record(
    *,
    action: str,
    actor_type: str = "user",
    actor_id: UUID | str | None = None,
    tenant_id: UUID | str | None = None,
    target_type: str = "",
    target_id: UUID | str | None = None,
    ip: str | None = None,
    user_agent: str = "",
    metadata: dict[str, Any] | None = None,
) -> None:
    with connection.cursor() as cursor:
        cursor.execute(
            _INSERT,
            [
                timezone.now(),
                tenant_id,
                actor_type,
                actor_id,
                action,
                target_type,
                target_id,
                ip,
                user_agent[:300],
                json.dumps(metadata or {}),
            ],
        )


def request_meta(request: HttpRequest) -> dict[str, Any]:
    """ip and user_agent for record(). Behind a reverse proxy, configure the proxy so that
    REMOTE_ADDR is the real client address; never trust a client-supplied X-Forwarded-For."""
    return {
        "ip": request.META.get("REMOTE_ADDR"),
        "user_agent": request.META.get("HTTP_USER_AGENT", ""),
    }