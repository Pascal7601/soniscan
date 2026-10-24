import pytest

from apps.domains.models import Domain
from apps.findings.library import sync_check_library
from apps.scans.models import Scan
from scanner.checks.email_auth import DmarcCheck
from scanner.types import CheckResult, Severity

DMARC_KEYS = set(DmarcCheck.emits)


@pytest.fixture
def library(db):
    """Load the shipped check library into the test database."""
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
        )

    return make


def dmarc_missing(asset="acme.example", **kwargs):
    return CheckResult("EMAIL_DMARC_MISSING", Severity.MEDIUM, 0.8, asset, **kwargs)


def dmarc_monitor_only(asset="acme.example", **kwargs):
    return CheckResult("EMAIL_DMARC_MONITOR_ONLY", Severity.MEDIUM, 0.8, asset, **kwargs)


def dmarc_multiple(asset="acme.example", **kwargs):
    return CheckResult("EMAIL_DMARC_MULTIPLE", Severity.MEDIUM, 0.5, asset, **kwargs)


def rdp_exposed(asset="acme.example", exploitability=1.0, **kwargs):
    return CheckResult("SVC_RDP_EXPOSED", Severity.CRITICAL, exploitability, asset, **kwargs)