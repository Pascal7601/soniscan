import logging

import pytest
from rest_framework.test import APIClient

from apps.core import tasks as core_tasks
from apps.domains.models import Domain
from apps.scans import services
from apps.scans.models import Scan


class FakeCelery:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send_task(self, name, args):
        if self.fail:
            raise ConnectionError("broker down")
        self.sent.append((name, args))


@pytest.fixture
def celery(monkeypatch):
    fake = FakeCelery()
    monkeypatch.setattr(core_tasks, "current_app", fake)
    return fake


@pytest.fixture
def domain(tenant_a):
    return Domain.objects.create(tenant=tenant_a, fqdn="acme.example")


def test_a_requested_scan_is_enqueued_only_after_the_transaction_commits(
    domain, celery, django_capture_on_commit_callbacks
):
    with django_capture_on_commit_callbacks(execute=False) as callbacks:
        scan = services.request_scan(domain=domain, mode=Scan.Mode.PASSIVE)
    assert celery.sent == []  # nothing is sent while the row could still be rolled back
    assert len(callbacks) == 1

    callbacks[0]()  # the commit happens
    assert celery.sent == [("runner.run_scan", [str(domain.tenant_id), str(scan.id)])]


def test_a_refused_request_enqueues_nothing(domain, celery, django_capture_on_commit_callbacks):
    with (
        django_capture_on_commit_callbacks(execute=True) as callbacks,
        pytest.raises(services.ActiveScansNotInPlan),
    ):
        services.request_scan(domain=domain, mode=Scan.Mode.ACTIVE)
    assert callbacks == []
    assert celery.sent == []


def test_a_broker_outage_does_not_lose_the_request(
    domain, monkeypatch, caplog, django_capture_on_commit_callbacks
):
    monkeypatch.setattr(core_tasks, "current_app", FakeCelery(fail=True))
    with caplog.at_level(logging.ERROR), django_capture_on_commit_callbacks(execute=True):
        scan = services.request_scan(domain=domain, mode=Scan.Mode.PASSIVE)

    # the row is committed; the reaper fails it if it never starts
    assert Scan.objects.filter(id=scan.id, status=Scan.Status.QUEUED).exists()
    assert "could not enqueue runner.run_scan" in caplog.text


def test_the_api_enqueues_the_scan(user_a, domain, celery, django_capture_on_commit_callbacks):
    client = APIClient()
    client.force_authenticate(user_a)
    with django_capture_on_commit_callbacks(execute=True):
        response = client.post(f"/api/v1/domains/{domain.id}/scans/", {}, format="json")
    assert response.status_code == 201
    assert celery.sent == [("runner.run_scan", [str(domain.tenant_id), response.json()["id"]])]