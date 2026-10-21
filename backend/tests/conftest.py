import pytest

from apps.accounts.models import Membership, Tenant, User


@pytest.fixture
def tenant_a(db) -> Tenant:
    return Tenant.objects.create(name="Acme Ltd")


@pytest.fixture
def tenant_b(db) -> Tenant:
    return Tenant.objects.create(name="Globex Ltd")


@pytest.fixture
def user_a(tenant_a) -> User:
    user = User.objects.create_user(email="a@acme.example", password="x" * 14)
    Membership.objects.create(tenant=tenant_a, user=user, role=Membership.Role.OWNER)
    return user


@pytest.fixture
def user_b(tenant_b) -> User:
    user = User.objects.create_user(email="b@globex.example", password="x" * 14)
    Membership.objects.create(tenant=tenant_b, user=user, role=Membership.Role.OWNER)
    return user
