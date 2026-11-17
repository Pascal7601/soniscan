"""Report generation. Views call this; it never touches HTTP.

A report is built in one transaction from the findings table as it stands after the latest
completed scan, then frozen: the full customer-facing text is copied into the snapshot, so later
library edits or fixed findings cannot rewrite history. The PDF is rendered from the snapshot
(apps.reports.pdf) whenever it is downloaded.
"""

import hashlib
import json
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from django.db import transaction
from django.utils import timezone

from apps.accounts.models import Tenant
from apps.core import audit
from apps.domains.models import Domain
from apps.findings import selectors as finding_selectors
from apps.findings.models import Finding
from scanner import scoring

from . import selectors
from .models import Report

SNAPSHOT_VERSION = 1
_EFFORT_RANK = {"minutes": 1, "hours": 2}


class ReportError(Exception):
    """Base class for report rule violations (mapped to HTTP errors at the API layer)."""


class NoCompletedScan(ReportError):
    pass


class IntegrityError(ReportError):
    """A stored snapshot no longer matches the hash recorded when it was created."""


def digest(snapshot: dict[str, Any]) -> str:
    canonical = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_integrity(report: Report) -> None:
    if digest(report.snapshot) != report.content_sha256:
        raise IntegrityError(f"report {report.id} does not match its recorded hash")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _ranking(finding: Finding) -> tuple[float, int, str]:
    """Highest score first; equally serious issues: quickest fix first (same rule as fix-first)."""
    effort = _EFFORT_RANK.get(finding.check_definition.effort, 3)
    return (-float(finding.score), effort, finding.asset)


def _open_entry(f: Finding, params: scoring.ScoringParams) -> dict[str, Any]:
    d = f.check_definition
    return {
        "finding_id": str(f.id),
        "check_key": d.check_key,
        "title": d.title,
        "asset": f.asset,
        "severity": f.severity,
        "score": float(f.score),
        "tier": scoring.tier(float(f.score), params),
        "plain_explanation": d.plain_explanation,
        "why_it_matters": d.why_it_matters,
        "fix_steps": list(d.fix_steps),
        "effort": d.effort,
        "owner_hint": d.owner_hint,
        "first_seen_at": _iso(f.first_seen_at),
        "reopened_count": f.reopened_count,
    }


@transaction.atomic
def generate_report(*, domain: Domain, actor_id: UUID | None = None) -> Report:
    scan = selectors.latest_completed_scan(tenant_id=domain.tenant_id, domain_id=domain.id)
    if scan is None:
        raise NoCompletedScan("Run a scan first: there is nothing to report on yet.")

    model = finding_selectors.current_scoring_model()
    params = scoring.ScoringParams.from_dict(model.params)
    tenant = Tenant.objects.get(id=domain.tenant_id)
    previous = selectors.latest_report(tenant_id=domain.tenant_id, domain_id=domain.id)
    now = timezone.now()
    report_id = uuid4()

    def findings(status: str) -> list[Finding]:
        return list(
            finding_selectors.list_findings(
                tenant_id=domain.tenant_id, domain_id=domain.id, status=status
            )
        )

    open_findings = sorted(findings("open"), key=_ranking)
    # One list feeds both the posture and the findings section, so they cannot disagree.
    posture = scoring.posture(
        [
            scoring.FindingInput(
                check_key=f.check_definition.check_key,
                severity=f.severity,
                exploitability=float(f.exploitability),
                exposure=float(f.exposure),
            )
            for f in open_findings
        ],
        params,
    )

    resolved: list[Finding] = []
    if previous is not None:
        resolved = [
            f for f in findings("fixed") if f.fixed_at and f.fixed_at > previous.generated_at
        ]

    snapshot: dict[str, Any] = {
        "version": SNAPSHOT_VERSION,
        "report_id": str(report_id),
        "generated_at": now.isoformat(),
        "organisation": tenant.name,
        "domain": domain.fqdn,
        "scan": {
            "id": str(scan.id),
            "mode": scan.mode,
            "status": scan.status,
            "finished_at": _iso(scan.finished_at or scan.queued_at),
        },
        "scoring_model_version": model.version,
        "posture": {
            "score": posture.score,
            "grade": posture.grade,
            "capped_by": posture.capped_by,
            "total_risk": posture.total_risk,
            "counts_by_tier": dict(posture.counts_by_tier),
        },
        "previous": (
            {
                "generated_at": previous.generated_at.isoformat(),
                "score": previous.score,
                "grade": previous.grade,
            }
            if previous
            else None
        ),
        "findings": [_open_entry(f, params) for f in open_findings],
        "accepted": [
            {
                "title": f.check_definition.title,
                "asset": f.asset,
                "severity": f.severity,
                "reason": f.accepted_reason,
                "until": _iso(f.accepted_until),
            }
            for f in findings("accepted_risk")
        ],
        "resolved": [
            {
                "title": f.check_definition.title,
                "asset": f.asset,
                "severity": f.severity,
                "fixed_at": _iso(f.fixed_at),
            }
            for f in sorted(resolved, key=lambda f: f.fixed_at or now)
        ],
    }

    report = Report.objects.create(
        id=report_id,
        tenant_id=domain.tenant_id,
        domain=domain,
        scan=scan,
        scoring_model=model,
        generated_by_id=actor_id,
        generated_at=now,
        score=posture.score,
        grade=posture.grade,
        open_findings=len(open_findings),
        snapshot_version=SNAPSHOT_VERSION,
        snapshot=snapshot,
        content_sha256=digest(snapshot),
    )
    audit.record(
        action="report.generated",
        actor_id=actor_id,
        tenant_id=domain.tenant_id,
        target_type="report",
        target_id=report.id,
        metadata={
            "domain": domain.fqdn,
            "scan_id": str(scan.id),
            "score": posture.score,
            "grade": posture.grade,
            "content_sha256": report.content_sha256,
        },
    )
    return report