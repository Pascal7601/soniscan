import pytest
from django.db import connection

from apps.domains.models import Domain
from apps.findings.library import sync_check_library
from apps.scans.models import Scan


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