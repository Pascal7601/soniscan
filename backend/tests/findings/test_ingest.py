import shutil
from datetime import timedelta
from decimal import Decimal

import pytest
from django.utils import timezone

from apps.core.models import AuditLog
from apps.domains.models import Domain
from apps.findings import services
from apps.findings.library import LIBRARY_DIR, sync_check_library
from apps.findings.models import Finding, FindingObservation
from scanner.types import CheckResult, Severity

from .conftest import DMARC_KEYS, dmarc_missing, rdp_exposed

pytestmark = pytest.mark.usefixtures("library")


def ingest(scan, results, covered=DMARC_KEYS):
    return services.ingest_results(scan=scan, results=results, covered_keys=covered)


# ---- creating and refreshing --------------------------------------------------------------------


def test_first_scan_creates_a_finding_with_evidence(domain, new_scan):
    scan = new_scan(domain)
    summary = ingest(scan, [dmarc_missing(evidence={"records": []})])

    assert (summary.new, summary.persisting, summary.fixed) == (1, 0, 0)
    finding = Finding.objects.get()
    assert finding.status == Finding.Status.OPEN
    assert finding.score == Decimal("3.20")  # medium 4 x exploitability 0.8 x exposure 1.0
    assert finding.first_seen_scan == finding.last_seen_scan == scan

    observation = FindingObservation.objects.get()
    assert observation.evidence == {"records": []}
    assert observation.scoring_model.version == 1
    assert observation.check_definition.version == 1


def test_exposure_lowers_the_score(domain, new_scan):
    ingest(new_scan(domain), [dmarc_missing(exposure=0.4)])
    assert Finding.objects.get().score == Decimal("1.28")


def test_the_same_issue_in_the_next_scan_stays_one_finding(domain, new_scan):
    first, second = new_scan(domain), new_scan(domain)
    ingest(first, [dmarc_missing()])
    summary = ingest(second, [dmarc_missing()])

    assert (summary.new, summary.persisting) == (0, 1)
    finding = Finding.objects.get()
    assert finding.first_seen_scan == first
    assert finding.last_seen_scan == second
    assert FindingObservation.objects.filter(finding=finding).count() == 2


def test_findings_are_tracked_per_asset(domain, new_scan):
    ingest(new_scan(domain), [dmarc_missing("acme.example"), dmarc_missing("mail.acme.example")])
    assert Finding.objects.count() == 2


def test_duplicate_results_in_one_scan_keep_the_highest_score(domain, new_scan):
    weak = CheckResult("EMAIL_DMARC_MISSING", Severity.LOW, 0.5, "acme.example")
    strong = CheckResult("EMAIL_DMARC_MISSING", Severity.HIGH, 0.9, "acme.example")
    ingest(new_scan(domain), [weak, strong])
    finding = Finding.objects.get()
    assert finding.severity == "high"
    assert finding.score == Decimal("6.30")


# ---- fixing ------------------------------------------------------------------------------------


def test_issue_that_disappears_is_fixed_when_its_check_completed(domain, new_scan):
    ingest(new_scan(domain), [dmarc_missing()])
    summary = ingest(new_scan(domain), [])

    assert summary.fixed == 1
    finding = Finding.objects.get()
    assert finding.status == Finding.Status.FIXED
    assert finding.fixed_at is not None


def test_a_failed_check_never_closes_findings(domain, new_scan):
    ingest(new_scan(domain), [dmarc_missing()])
    summary = ingest(new_scan(domain), [], covered=set())  # the DMARC check errored out

    assert summary.fixed == 0
    assert Finding.objects.get().status == Finding.Status.OPEN


def test_checks_that_cover_other_keys_do_not_close_unrelated_findings(domain, new_scan):
    ingest(new_scan(domain), [dmarc_missing()])
    ingest(new_scan(domain), [], covered={"SVC_RDP_EXPOSED"})
    assert Finding.objects.get().status == Finding.Status.OPEN


def test_a_passive_scan_cannot_close_an_active_finding(verified_domain, new_scan):
    ingest(new_scan(verified_domain), [rdp_exposed()], covered={"SVC_RDP_EXPOSED"})
    ingest(new_scan(verified_domain), [], covered=DMARC_KEYS)  # passive checks only
    assert Finding.objects.get().status == Finding.Status.OPEN


def test_scans_of_one_domain_never_touch_another_domains_findings(tenant_a, domain, new_scan):
    other = Domain.objects.create(tenant=tenant_a, fqdn="other.example")
    ingest(new_scan(domain), [dmarc_missing()])
    ingest(new_scan(other), [])
    assert Finding.objects.get().status == Finding.Status.OPEN


# ---- reopening ---------------------------------------------------------------------------------


def test_a_fixed_issue_that_returns_is_reopened(domain, new_scan):
    ingest(new_scan(domain), [dmarc_missing()])
    ingest(new_scan(domain), [])
    summary = ingest(new_scan(domain), [dmarc_missing()])

    assert summary.reopened == 1
    finding = Finding.objects.get()
    assert finding.status == Finding.Status.OPEN
    assert finding.fixed_at is None
    assert finding.reopened_count == 1


# ---- accepted risk -----------------------------------------------------------------------------


def _accept(finding, user, days=30):
    return services.accept_risk(
        finding=finding,
        actor_id=user.id,
        reason="Legacy system, replacement planned",
        until=timezone.now() + timedelta(days=days),
    )


def test_accepted_risk_survives_rescans_while_valid(domain, new_scan, user_a):
    ingest(new_scan(domain), [dmarc_missing()])
    _accept(Finding.objects.get(), user_a)
    summary = ingest(new_scan(domain), [dmarc_missing()])

    assert summary.persisting == 1
    assert Finding.objects.get().status == Finding.Status.ACCEPTED_RISK


def test_expired_acceptance_reopens_the_finding(domain, new_scan, user_a):
    ingest(new_scan(domain), [dmarc_missing()])
    _accept(Finding.objects.get(), user_a)
    Finding.objects.update(accepted_until=timezone.now() - timedelta(minutes=1))

    summary = ingest(new_scan(domain), [dmarc_missing()])

    assert summary.reopened == 1
    finding = Finding.objects.get()
    assert finding.status == Finding.Status.OPEN
    assert (finding.accepted_by, finding.accepted_reason, finding.accepted_until) == (None, "", None)


def test_accepted_finding_is_fixed_when_the_issue_goes_away(domain, new_scan, user_a):
    ingest(new_scan(domain), [dmarc_missing()])
    _accept(Finding.objects.get(), user_a)
    ingest(new_scan(domain), [])
    assert Finding.objects.get().status == Finding.Status.FIXED


def test_accepting_a_risk_is_audited(domain, new_scan, user_a):
    ingest(new_scan(domain), [dmarc_missing()])
    finding = _accept(Finding.objects.get(), user_a)
    event = AuditLog.objects.get(action="finding.risk_accepted", target_id=finding.id)
    assert event.actor_id == user_a.id
    assert event.metadata["check_key"] == "EMAIL_DMARC_MISSING"
    assert event.metadata["reason"] == "Legacy system, replacement planned"


@pytest.mark.parametrize(
    ("reason", "days", "message"),
    [
        ("", 30, "reason"),
        ("   ", 30, "reason"),
        ("ok reason", -1, "future"),
        ("ok reason", 400, "longer"),
    ],
)
def test_risk_acceptance_rules(domain, new_scan, user_a, reason, days, message):
    ingest(new_scan(domain), [dmarc_missing()])
    with pytest.raises(services.InvalidTransition, match=message):
        services.accept_risk(
            finding=Finding.objects.get(),
            actor_id=user_a.id,
            reason=reason,
            until=timezone.now() + timedelta(days=days),
        )


def test_only_open_findings_can_be_accepted(domain, new_scan, user_a):
    ingest(new_scan(domain), [dmarc_missing()])
    ingest(new_scan(domain), [])  # now fixed
    with pytest.raises(services.InvalidTransition, match="open"):
        _accept(Finding.objects.get(), user_a)


# ---- safety ------------------------------------------------------------------------------------


def test_unknown_check_key_fails_loudly_and_writes_nothing(domain, new_scan):
    bad = CheckResult("NOT_IN_LIBRARY", Severity.LOW, 0.5, "acme.example")
    with pytest.raises(services.UnknownCheck, match="NOT_IN_LIBRARY"):
        ingest(new_scan(domain), [dmarc_missing(), bad])
    assert Finding.objects.count() == 0
    assert FindingObservation.objects.count() == 0


def test_retired_checks_cannot_be_ingested(domain, new_scan, tmp_path):
    work = tmp_path / "lib"
    shutil.copytree(LIBRARY_DIR, work)
    (work / "email.toml").unlink()
    sync_check_library(work)
    with pytest.raises(services.UnknownCheck):
        ingest(new_scan(domain), [dmarc_missing()])


def test_new_library_version_applies_on_the_next_scan_without_rewriting_history(
    domain, new_scan, tmp_path
):
    ingest(new_scan(domain), [dmarc_missing()])

    work = tmp_path / "lib"
    shutil.copytree(LIBRARY_DIR, work)
    email = work / "email.toml"
    email.write_text(email.read_text().replace("Anyone can send emails", "Anybody can send emails"))
    sync_check_library(work)

    ingest(new_scan(domain), [dmarc_missing()])

    finding = Finding.objects.select_related("check_definition").get()
    assert finding.check_definition.version == 2
    versions = list(
        FindingObservation.objects.order_by("observed_at").values_list(
            "check_definition__version", flat=True
        )
    )
    assert versions == [1, 2]  # the first observation still points at the text it was shown with