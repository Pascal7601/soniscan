"""Runner services: all the logic behind the Celery tasks in tasks.py.

execute_scan() is three short transactions around a network phase that holds NO transaction:

    1. CLAIM   queued -> running (one conditional UPDATE)         \\
    2. RUN     scanner checks (DNS / HTTP / TLS, no database)      } tenant context is set in 1 and 3
    3. FINISH  ingest findings + final status + audit event       /

Every database block runs inside `tenant_context(tenant_id)`: the worker's database role can only see
and change one tenant's rows once `app.current_tenant` is set (row-level security).
"""

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from uuid import UUID

from django.conf import settings
from django.db import IntegrityError, transaction
from django.utils import timezone

import scanner
import scanner.checks  # noqa: F401  (importing registers every check; without it none would run)
from apps.core import audit
from apps.core.tenancy import tenant_context
from apps.findings import services as findings
from apps.scans.models import Scan
from scanner import runner
from scanner.dns import DnsPythonResolver
from scanner.net import StdlibTlsProbe, StdlibWebClient
from scanner.types import Check, CheckContext, Resolver, TlsProbe, WebClient

logger = logging.getLogger(__name__)


class ExecutionResult(StrEnum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    REFUSED = "refused"
    SKIPPED = "skipped"  # not queued: already claimed, finished, unknown, or another tenant's


@dataclass(frozen=True)
class _Job:
    fqdn: str
    active: bool
    verified: bool


def default_resolver() -> Resolver:
    return DnsPythonResolver(
        timeout=settings.SCANNER_DNS_TIMEOUT,
        nameservers=settings.SCANNER_DNS_SERVERS or None,
        canary=settings.SCANNER_DNS_CANARY or None,
    )


def default_tls_probe() -> TlsProbe:
    return StdlibTlsProbe(timeout=settings.SCANNER_NET_TIMEOUT)


def default_web_client() -> WebClient:
    return StdlibWebClient(timeout=settings.SCANNER_NET_TIMEOUT)


# ---- phase 1: claim ----------------------------------------------------------------------------


def _claim(tenant_id: UUID, scan_id: UUID) -> _Job | ExecutionResult:
    now = timezone.now()
    try:
        with tenant_context(tenant_id):
            claimed = Scan.objects.filter(
                id=scan_id, tenant_id=tenant_id, status=Scan.Status.QUEUED
            ).update(status=Scan.Status.RUNNING, started_at=now, updated_at=now)
            if not claimed:
                return ExecutionResult.SKIPPED
            scan = Scan.objects.select_related("domain").get(id=scan_id, tenant_id=tenant_id)
            return _Job(
                fqdn=scan.domain.fqdn,
                active=scan.mode == Scan.Mode.ACTIVE,
                verified=scan.domain.is_verified_now(),
            )
    except IntegrityError:
        # The database guard rejected an active scan whose domain verification has lapsed. The
        # claim's transaction is rolled back; record the refusal in a fresh one.
        with tenant_context(tenant_id):
            Scan.objects.filter(id=scan_id, tenant_id=tenant_id).update(
                status=Scan.Status.REFUSED, finished_at=timezone.now(), updated_at=timezone.now()
            )
            audit.record(
                action="scan.refused",
                actor_type="scanner",
                tenant_id=tenant_id,
                target_type="scan",
                target_id=scan_id,
                metadata={"reason": "domain_not_verified"},
            )
        return ExecutionResult.REFUSED


# ---- phase 3: finish ---------------------------------------------------------------------------


def _finish(tenant_id: UUID, scan_id: UUID, outcome: runner.RunOutcome) -> ExecutionResult:
    errors = [f"{f.check_key}: {f.error}" for f in outcome.failures]
    summary = None
    ingest_failed = False

    with tenant_context(tenant_id):
        scan = Scan.objects.select_related("domain").get(id=scan_id, tenant_id=tenant_id)

        # Nothing completed -> nothing can be concluded, so no finding is created or closed.
        if outcome.completed:
            try:
                with transaction.atomic():  # a savepoint: a failed ingest leaves no partial rows
                    summary = findings.ingest_results(
                        scan=scan, results=outcome.results, covered_keys=outcome.covered_keys
                    )
            except findings.FindingError as exc:
                ingest_failed = True
                errors.insert(0, f"ingest: {exc}")

        if ingest_failed or (outcome.failures and not outcome.completed):
            status, result = Scan.Status.FAILED, ExecutionResult.FAILED
        elif outcome.failures:
            status, result = Scan.Status.PARTIAL, ExecutionResult.PARTIAL
        else:
            status, result = Scan.Status.SUCCEEDED, ExecutionResult.SUCCEEDED

        now = timezone.now()
        Scan.objects.filter(id=scan_id, tenant_id=tenant_id).update(
            status=status,
            finished_at=now,
            updated_at=now,
            scanner_version=scanner.__version__,
            error="; ".join(errors)[:2000],
        )
        audit.record(
            action="scan.completed",
            actor_type="scanner",
            tenant_id=tenant_id,
            target_type="scan",
            target_id=scan_id,
            metadata={
                "status": status.value,
                "findings": {
                    "new": summary.new if summary else 0,
                    "reopened": summary.reopened if summary else 0,
                    "persisting": summary.persisting if summary else 0,
                    "fixed": summary.fixed if summary else 0,
                },
                "failed_checks": [f.check_key for f in outcome.failures],
            },
        )
    return result


def _fail_unexpected(tenant_id: UUID, scan_id: UUID) -> None:
    """Best effort: never let a problem while recording a failure hide the original error."""
    try:
        with tenant_context(tenant_id):
            now = timezone.now()
            Scan.objects.filter(id=scan_id, tenant_id=tenant_id, status=Scan.Status.RUNNING).update(
                status=Scan.Status.FAILED, finished_at=now, updated_at=now,
                scanner_version=scanner.__version__, error="execution_error",
            )  # fmt: skip
            audit.record(
                action="scan.failed",
                actor_type="scanner",
                tenant_id=tenant_id,
                target_type="scan",
                target_id=scan_id,
                metadata={"reason": "execution_error"},
            )
    except Exception:
        logger.exception("could not record failure of scan %s", scan_id)


# ---- the entry point ---------------------------------------------------------------------------


def execute_scan(
    *,
    tenant_id: UUID,
    scan_id: UUID,
    resolver: Resolver | None = None,
    checks: Sequence[Check] | None = None,
    tls: TlsProbe | None = None,
    web: WebClient | None = None,
) -> ExecutionResult:
    logger.info("executing scan %s for tenant %s", scan_id, tenant_id)

    job = _claim(tenant_id, scan_id)
    if isinstance(job, ExecutionResult):
        logger.info("scan %s: %s", scan_id, job.value)
        return job

    try:
        ctx = CheckContext(
            domain=job.fqdn,
            resolver=resolver or default_resolver(),
            verified=job.verified,
            tls=tls or default_tls_probe(),
            web=web or default_web_client(),
        )
        to_run = (
            list(checks)
            if checks is not None
            else runner.select_checks(active=job.active, verified=job.verified)
        )
        outcome = runner.run_checks(to_run, ctx)  # no transaction is open here
        return _finish(tenant_id, scan_id, outcome)
    except Exception:
        _fail_unexpected(tenant_id, scan_id)
        raise