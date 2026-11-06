import pytest
from django.db import connection

from apps.domains.models import Domain
from apps.findings.library import sync_check_library
from apps.scans.models import Scan
from scanner.types import TlsObservation


class FakeResolver:
    """Maps DNS names to TXT values; a value that is an exception class/instance is raised."""

    def __init__(self, records=None):
        self.records = records or {}

    def txt(self, name):
        value = self.records.get(name, [])
        if isinstance(value, BaseException) or (
            isinstance(value, type) and issubclass(value, BaseException)
        ):
            raise value if isinstance(value, BaseException) else value()
        return value


@pytest.fixture
def library(db):
    return sync_check_library()


@pytest.fixture
def domain(tenant_a):
    return Domain.objects.create(tenant=tenant_a, fqdn="acme.example")


@pytest.fixture
def queued_scan(domain):
    return Scan.objects.create(
        tenant_id=domain.tenant_id,
        domain=domain,
        mode=Scan.Mode.PASSIVE,
        trigger_type=Scan.Trigger.MANUAL,
    )


@pytest.fixture
def worker_role(db):
    """Switch this transaction to the scanner_worker role using ONLY the grants the migration gave
    it (no extra GRANTs here), so tests prove those grants are both sufficient and minimal."""

    def switch():
        with connection.cursor() as cur:
            cur.execute("SELECT 1 FROM pg_roles WHERE rolname = 'scanner_worker'")
            if cur.fetchone() is None:
                pytest.skip("scanner_worker role missing; run infra/postgres/init.sql")
            cur.execute("SET LOCAL ROLE scanner_worker")

    return switch


class NoWebsiteTls:
    """A host with no public web presence: the TLS check has nothing to judge."""

    def probe(self, host):
        return TlsObservation(resolved=False, reachable=False)


class FakeTls:
    def __init__(self, observed):
        self.observed = observed

    def probe(self, host):
        return self.observed


class NoWebsite:
    """Nothing answers on ports 80 or 443."""

    def get(self, url):
        return None


class FakeWeb:
    """Maps URLs to WebResponse objects (or exceptions to raise); unknown URLs return None."""

    def __init__(self, pages=None):
        self.pages = pages or {}
        self.urls = []

    def get(self, url):
        self.urls.append(url)
        page = self.pages.get(url)
        if isinstance(page, BaseException):
            raise page
        return page