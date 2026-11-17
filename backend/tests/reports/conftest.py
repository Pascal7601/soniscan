import pytest
from django.utils import timezone

from apps.domains.models import Domain
from apps.findings.library import sync_check_library
from apps.scans.models import Scan
from scanner.types import CheckResult, Severity

DMARC_KEYS = {"EMAIL_DMARC_MISSING", "EMAIL_DMARC_MONITOR_ONLY", "EMAIL_DMARC_MULTIPLE"}
RDP_KEYS = {"SVC_RDP_EXPOSED"}


def dmarc_missing(asset="acme.example"):
    return CheckResult("EMAIL_DMARC_MISSING", Severity.MEDIUM, 0.8, asset)


def rdp_exposed(asset="acme.example"):
    return CheckResult("SVC_RDP_EXPOSED", Severity.CRITICAL, 1.0, asset)


@pytest.fixture
def library(db):
    return sync_check_library()


@pytest.fixture
def domain(tenant_a):
    return Domain.objects.create(tenant=tenant_a, fqdn="acme.example")


@pytest.fixture
def new_scan():
    def make(domain, status=Scan.Status.SUCCEEDED):
        return Scan.objects.create(
            tenant_id=domain.tenant_id,
            domain=domain,
            mode=Scan.Mode.PASSIVE,
            trigger_type=Scan.Trigger.MANUAL,
            status=status,
            finished_at=timezone.now() if status != Scan.Status.QUEUED else None,
        )

    return make


@pytest.fixture
def scanned_domain(domain, new_scan, library):
    """A domain whose latest scan found a missing DMARC record and an exposed remote desktop."""
    from apps.findings import services

    services.ingest_results(
        scan=new_scan(domain),
        results=[dmarc_missing(), rdp_exposed()],
        covered_keys=DMARC_KEYS | RDP_KEYS,
    )
    return domain