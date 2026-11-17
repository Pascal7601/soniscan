from datetime import timedelta

import pytest
from django.db import DatabaseError, transaction
from django.utils import timezone

from apps.accounts.models import User
from apps.core.models import AuditLog
from apps.findings import services as finding_services
from apps.findings.models import Finding
from apps.reports import services
from apps.reports.models import Report
from apps.scans.models import Scan

from .conftest import DMARC_KEYS, RDP_KEYS, dmarc_missing

pytestmark = pytest.mark.usefixtures("library")


def test_a_report_freezes_the_posture_and_the_text_shown(scanned_domain, user_a):
    report = services.generate_report(domain=scanned_domain, actor_id=user_a.id)

    assert (report.score, report.grade, report.open_findings) == (69, "D", 2)  # critical cap
    snap = report.snapshot
    assert snap["posture"]["capped_by"] == "critical"
    assert snap["organisation"] == "Acme Ltd"
    assert snap["domain"] == "acme.example"
    assert snap["scoring_model_version"] == 1
    # The most serious issue comes first, with the library text copied in.
    first = snap["findings"][0]
    assert first["check_key"] == "SVC_RDP_EXPOSED"
    assert first["tier"] == "fix_now"
    assert first["fix_steps"] and first["plain_explanation"]
    assert services.digest(snap) == report.content_sha256


def test_the_snapshot_matches_the_live_posture(scanned_domain):
    report = services.generate_report(domain=scanned_domain)
    live = finding_services.compute_posture(
        tenant_id=scanned_domain.tenant_id, domain_id=scanned_domain.id
    )
    assert report.score == live.score
    assert report.snapshot["posture"]["total_risk"] == live.total_risk


def test_stored_snapshot_still_matches_its_hash_after_a_round_trip(scanned_domain):
    report = services.generate_report(domain=scanned_domain)
    stored = Report.objects.get(id=report.id)
    services.verify_integrity(stored)  # must not raise


def test_generation_is_audited(scanned_domain, user_a):
    report = services.generate_report(domain=scanned_domain, actor_id=user_a.id)
    row = AuditLog.objects.get(action="report.generated")
    assert row.target_id == report.id
    assert row.metadata["content_sha256"] == report.content_sha256


def test_nothing_to_report_before_a_scan_completes(domain, new_scan):
    new_scan(domain, status=Scan.Status.QUEUED)
    new_scan(domain, status=Scan.Status.FAILED)
    with pytest.raises(services.NoCompletedScan):
        services.generate_report(domain=domain)


def test_a_partial_scan_is_reported_as_such(domain, new_scan):
    scan = new_scan(domain, status=Scan.Status.PARTIAL)
    finding_services.ingest_results(scan=scan, results=[dmarc_missing()], covered_keys=DMARC_KEYS)
    report = services.generate_report(domain=domain)
    assert report.snapshot["scan"]["status"] == "partial"


def test_the_next_report_shows_progress(scanned_domain, new_scan):
    first = services.generate_report(domain=scanned_domain)
    assert first.snapshot["previous"] is None and first.snapshot["resolved"] == []

    # Second scan: the remote desktop is gone and its check completed, so it is marked fixed.
    finding_services.ingest_results(
        scan=new_scan(scanned_domain),
        results=[dmarc_missing()],
        covered_keys=DMARC_KEYS | RDP_KEYS,
    )
    second = services.generate_report(domain=scanned_domain)

    assert second.snapshot["previous"]["score"] == first.score
    assert [r["title"] for r in second.snapshot["resolved"]] == [
        Finding.objects.get(check_definition__check_key="SVC_RDP_EXPOSED").check_definition.title
    ]
    assert second.score > first.score
    assert second.open_findings == 1


def test_accepted_risks_are_listed_but_not_scored(scanned_domain, user_a):
    rdp = Finding.objects.get(check_definition__check_key="SVC_RDP_EXPOSED")
    finding_services.accept_risk(
        finding=rdp,
        actor_id=user_a.id,
        reason="Isolated lab machine, reviewed by IT",
        until=timezone.now() + timedelta(days=30),
    )
    report = services.generate_report(domain=scanned_domain)

    assert report.open_findings == 1
    assert [a["reason"] for a in report.snapshot["accepted"]] == [
        "Isolated lab machine, reviewed by IT"
    ]
    assert all(f["check_key"] != "SVC_RDP_EXPOSED" for f in report.snapshot["findings"])


def test_a_report_does_not_change_when_findings_are_fixed(scanned_domain, new_scan):
    report = services.generate_report(domain=scanned_domain)
    finding_services.ingest_results(
        scan=new_scan(scanned_domain), results=[], covered_keys=DMARC_KEYS | RDP_KEYS
    )
    assert Report.objects.get(id=report.id).snapshot == report.snapshot


def test_a_tampered_snapshot_is_detected(scanned_domain):
    report = services.generate_report(domain=scanned_domain)
    report.snapshot["posture"]["score"] = 100
    with pytest.raises(services.IntegrityError):
        services.verify_integrity(report)


def test_the_database_refuses_to_edit_a_report(scanned_domain):
    report = services.generate_report(domain=scanned_domain)
    with pytest.raises(DatabaseError, match="immutable"), transaction.atomic():
        Report.objects.filter(id=report.id).update(score=100)
    with pytest.raises(DatabaseError, match="immutable"), transaction.atomic():
        Report.objects.filter(id=report.id).update(snapshot={})


def test_deleting_the_author_keeps_the_report(scanned_domain, user_a):
    report = services.generate_report(domain=scanned_domain, actor_id=user_a.id)
    User.objects.filter(id=user_a.id).delete()
    report.refresh_from_db()
    assert report.generated_by_id is None