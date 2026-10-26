"""Celery entry points. Thin on purpose: all logic lives in services.py and is tested there.

Delivery is at-least-once (acks_late), so every task must be safe to run twice. A redelivered
run_scan finds the scan no longer queued and returns "skipped"; if a worker dies mid-scan the
reaper fails the stuck scan so the customer can simply retry.
"""

from uuid import UUID

from celery import shared_task
from django.db import OperationalError

from . import services


@shared_task(
    name="runner.run_scan",
    acks_late=True,
    soft_time_limit=300,
    time_limit=330,
    autoretry_for=(OperationalError,),  # database blips only; nothing has changed yet when it fires
    retry_backoff=True,
    retry_jitter=True,
    max_retries=3,
)
def run_scan(tenant_id: str, scan_id: str) -> str:
    return services.execute_scan(tenant_id=UUID(tenant_id), scan_id=UUID(scan_id)).value


@shared_task(
    name="runner.verify_domain",
    acks_late=True,
    soft_time_limit=60,
    time_limit=90,
    autoretry_for=(OperationalError,),
    retry_backoff=True,
    max_retries=3,
)
def verify_domain(tenant_id: str, domain_id: str) -> str:
    outcome = services.check_domain_verification(
        tenant_id=UUID(tenant_id), domain_id=UUID(domain_id)
    )
    return outcome.value


@shared_task(name="runner.reap_stale_scans", soft_time_limit=120)
def reap_stale_scans() -> int:
    return services.reap_stale_scans()