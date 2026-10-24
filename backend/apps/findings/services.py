"""Finding lifecycle and scoring. Views call these; they never touch HTTP.

Lifecycle rules applied after every scan (ingest_results):
  * seen now, never seen before            -> new finding (open)
  * seen now, currently open               -> stays open, score and evidence refreshed
  * seen now, previously fixed             -> reopened (reopened_count + 1)
  * seen now, risk acceptance has expired  -> reopened
  * not seen now, its check COMPLETED      -> fixed
  * not seen now, its check did NOT run    -> untouched (a failed or skipped check must never
                                              silently close findings)
"""

import hashlib
from collections.abc import Collection, Sequence
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from uuid import UUID

from django.db import transaction
from django.utils import timezone

from apps.core import audit
from apps.scans.models import Scan
from scanner import scoring
from scanner.types import CheckResult

from . import selectors
from .models import CheckDefinition, Finding, FindingObservation

MAX_RISK_ACCEPTANCE_DAYS = 365


class FindingError(Exception):
    """Base class for finding rule violations."""


class UnknownCheck(FindingError):
    """A check emitted a key that has no active library entry. Fails loudly by design."""


class InvalidTransition(FindingError):
    pass


@dataclass(frozen=True)
class IngestSummary:
    new: int
    reopened: int
    persisting: int
    fixed: int


def fingerprint(check_key: str, asset: str) -> str:
    return hashlib.sha256(f"{check_key}|{asset}".encode()).hexdigest()


def _dec(value: float) -> Decimal:
    return Decimal(str(round(value, 2)))


@transaction.atomic
def ingest_results(
    *, scan: Scan, results: Sequence[CheckResult], covered_keys: Collection[str]
) -> IngestSummary:
    """Apply one scan's results to the domain's findings.

    `covered_keys` are the finding keys of the checks that COMPLETED in this scan (the union of
    their `emits`). Only those are eligible to be marked fixed.
    """
    model = selectors.current_scoring_model()
    params = scoring.ScoringParams.from_dict(model.params)
    now = timezone.now()

    # Latest active definition per key; a missing one is an error, never a silent skip.
    needed = {r.check_key for r in results}
    definitions: dict[str, CheckDefinition] = {}
    for d in CheckDefinition.objects.filter(is_active=True, check_key__in=needed).order_by(
        "version"
    ):
        definitions[d.check_key] = d
    unknown = needed - definitions.keys()
    if unknown:
        raise UnknownCheck(f"no active check library entry for: {', '.join(sorted(unknown))}")

    # One result per (check, asset): keep the highest-scoring if a check reports duplicates.
    by_fingerprint: dict[str, tuple[CheckResult, float]] = {}
    for r in results:
        score = scoring.finding_score(r.severity, r.exploitability, r.exposure, params)
        fp = fingerprint(r.check_key, r.asset)
        if fp not in by_fingerprint or score > by_fingerprint[fp][1]:
            by_fingerprint[fp] = (r, score)

    # of=("self",): lock only the findings rows. A plain FOR UPDATE would also lock the joined
    # check_definitions rows, which needs UPDATE rights the application role deliberately lacks.
    existing = {
        f.fingerprint: f
        for f in Finding.objects.select_for_update(of=("self",))
        .filter(domain_id=scan.domain_id)
        .select_related("check_definition")
    }

    new = reopened = persisting = 0
    for fp, (r, score) in by_fingerprint.items():
        definition = definitions[r.check_key]
        values = {
            "severity": str(r.severity),
            "exploitability": _dec(r.exploitability),
            "exposure": _dec(r.exposure),
            "score": _dec(score),
        }
        finding = existing.get(fp)
        if finding is None:
            finding = Finding.objects.create(
                tenant_id=scan.tenant_id,
                domain_id=scan.domain_id,
                check_definition=definition,
                asset=r.asset,
                fingerprint=fp,
                first_seen_scan=scan,
                last_seen_scan=scan,
                first_seen_at=now,
                last_seen_at=now,
                **values,
            )
            new += 1
        else:
            if _should_reopen(finding, now):
                finding.status = Finding.Status.OPEN
                finding.fixed_at = None
                finding.accepted_by = None
                finding.accepted_reason = ""
                finding.accepted_until = None
                finding.reopened_count += 1
                reopened += 1
            else:
                persisting += 1
            finding.check_definition = definition
            finding.last_seen_scan = scan
            finding.last_seen_at = now
            for name, value in values.items():
                setattr(finding, name, value)
            finding.save()
        FindingObservation.objects.create(
            tenant_id=scan.tenant_id,
            finding=finding,
            scan=scan,
            check_definition=definition,
            scoring_model=model,
            observed_at=now,
            evidence=r.evidence,
            **values,
        )

    fixed = 0
    closable = (Finding.Status.OPEN, Finding.Status.ACCEPTED_RISK)
    for fp, finding in existing.items():
        if fp in by_fingerprint or finding.status not in closable:
            continue
        if finding.check_definition.check_key in covered_keys:
            finding.status = Finding.Status.FIXED
            finding.fixed_at = now
            finding.save(update_fields=["status", "fixed_at"])
            fixed += 1

    return IngestSummary(new=new, reopened=reopened, persisting=persisting, fixed=fixed)


def _should_reopen(finding: Finding, now: datetime) -> bool:
    if finding.status == Finding.Status.FIXED:
        return True
    return (
        finding.status == Finding.Status.ACCEPTED_RISK
        and finding.accepted_until is not None
        and finding.accepted_until <= now
    )


def compute_posture(*, tenant_id: UUID, domain_id: UUID) -> scoring.PostureResult:
    """Overall score from OPEN findings only (fixed and accepted ones do not count)."""
    params = scoring.ScoringParams.from_dict(selectors.current_scoring_model().params)
    inputs = [
        scoring.FindingInput(
            check_key=f.check_definition.check_key,
            severity=f.severity,
            exploitability=float(f.exploitability),
            exposure=float(f.exposure),
        )
        for f in selectors.list_findings(tenant_id=tenant_id, domain_id=domain_id, status="open")
    ]
    return scoring.posture(inputs, params)


@transaction.atomic
def accept_risk(*, finding: Finding, actor_id: UUID, reason: str, until: datetime) -> Finding:
    """Record that the business knowingly accepts a risk. Time-boxed so it is re-reviewed."""
    now = timezone.now()
    if finding.status != Finding.Status.OPEN:
        raise InvalidTransition("Only open findings can be accepted.")
    if not reason.strip():
        raise InvalidTransition("A reason is required.")
    if until <= now:
        raise InvalidTransition("The review date must be in the future.")
    if (until - now).days > MAX_RISK_ACCEPTANCE_DAYS:
        raise InvalidTransition(
            f"Acceptance cannot last longer than {MAX_RISK_ACCEPTANCE_DAYS} days."
        )

    finding.status = Finding.Status.ACCEPTED_RISK
    finding.accepted_by_id = actor_id
    finding.accepted_reason = reason.strip()
    finding.accepted_until = until
    finding.save(update_fields=["status", "accepted_by", "accepted_reason", "accepted_until"])
    audit.record(
        action="finding.risk_accepted",
        actor_id=actor_id,
        tenant_id=finding.tenant_id,
        target_type="finding",
        target_id=finding.id,
        metadata={
            "check_key": finding.check_definition.check_key,
            "asset": finding.asset,
            "severity": finding.severity,
            "until": until.isoformat(),
            "reason": finding.accepted_reason,
        },
    )
    return finding