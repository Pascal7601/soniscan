import pytest
from django.core.cache import cache
from rest_framework.test import APIClient
from rest_framework.throttling import ScopedRateThrottle

from apps.core import tasks as core_tasks
from apps.core.models import AuditLog
from apps.domains import services
from apps.domains.models import Domain


class FakeCelery:
    def __init__(self):
        self.sent = []

    def send_task(self, name, args):
        self.sent.append((name, args))


@pytest.fixture
def celery(monkeypatch):
    fake = FakeCelery()
    monkeypatch.setattr(core_tasks, "current_app", fake)
    return fake


@pytest.fixture
def domain(tenant_a):
    return Domain.objects.create(tenant=tenant_a, fqdn="acme.example")


def client_for(user):
    client = APIClient()
    client.force_authenticate(user)
    return client


def url(domain):
    return f"/api/v1/domains/{domain.id}/verification/check/"


def test_check_is_queued_for_a_pending_verification(
    user_a, domain, celery, django_capture_on_commit_callbacks
):
    services.start_verification(domain=domain)
    with django_capture_on_commit_callbacks(execute=True):
        response = client_for(user_a).post(url(domain))

    assert response.status_code == 202
    assert response.json() == {"status": "queued"}
    assert celery.sent == [("runner.verify_domain", [str(domain.tenant_id), str(domain.id)])]
    event = AuditLog.objects.get(action="domain.verification_check_requested")
    assert event.actor_id == user_a.id


def test_check_needs_a_started_verification_first(user_a, domain, celery):
    response = client_for(user_a).post(url(domain))
    assert response.status_code == 409
    assert "Start verification" in response.json()["detail"]
    assert celery.sent == []


def test_already_verified_domains_are_not_rechecked(user_a, verified_domain, celery):
    response = client_for(user_a).post(url(verified_domain))
    assert response.status_code == 200
    assert response.json() == {"status": "already_verified"}
    assert celery.sent == []


def test_other_tenants_domains_are_not_found(user_b, domain, celery):
    services.start_verification(domain=domain)
    assert client_for(user_b).post(url(domain)).status_code == 404
    assert celery.sent == []


def test_checks_are_rate_limited(user_a, domain, celery, monkeypatch):
    monkeypatch.setattr(ScopedRateThrottle, "THROTTLE_RATES", {"verification_check": "2/min"})
    cache.clear()
    services.start_verification(domain=domain)
    client = client_for(user_a)
    codes = [client.post(url(domain)).status_code for _ in range(3)]
    assert codes == [202, 202, 429]
    cache.clear()


def test_a_missed_check_keeps_the_token_usable(domain):
    """Regression: a mismatch used to mark the attempt failed, burning the one-time token."""
    verification, token = services.start_verification(domain=domain)
    assert not services.complete_verification(verification=verification, observed_values=[])
    verification.refresh_from_db()
    assert verification.result == "pending"
    assert services.complete_verification(
        verification=verification, observed_values=[f"{services.TXT_PREFIX}{token}"]
    )