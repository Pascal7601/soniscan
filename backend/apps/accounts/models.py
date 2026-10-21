from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.db import models
from django.db.models.functions import Lower

from apps.core.models import BaseModel


class Tenant(BaseModel):
    class Plan(models.TextChoices):
        FREE = "free"
        STARTER = "starter"
        BUSINESS = "business"

    class Status(models.TextChoices):
        ACTIVE = "active"
        SUSPENDED = "suspended"
        CLOSED = "closed"

    name = models.CharField(max_length=200)
    plan = models.CharField(max_length=20, choices=Plan.choices, default=Plan.FREE)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.ACTIVE)
    deleted_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = "tenants"

    def __str__(self) -> str:
        return self.name


class UserManager(BaseUserManager["User"]):
    use_in_migrations = True

    def create_user(self, email: str, password: str | None = None, **extra):
        if not email:
            raise ValueError("email is required")
        user = self.model(email=self.normalize_email(email).lower(), **extra)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email: str, password: str | None = None, **extra):
        extra.setdefault("is_staff", True)
        extra.setdefault("is_superuser", True)
        return self.create_user(email, password, **extra)


class User(BaseModel, AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True)  # stored lowercase, enforced by a constraint
    display_name = models.CharField(max_length=200, blank=True)
    mfa_enabled = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)

    USERNAME_FIELD = "email"
    objects = UserManager()

    class Meta:
        db_table = "users"
        constraints = [
            models.CheckConstraint(
                condition=models.Q(email=Lower("email")), name="users_email_lowercase"
            ),
        ]

    def __str__(self) -> str:
        return str(self.email)


class Membership(BaseModel):
    class Role(models.TextChoices):
        OWNER = "owner"
        ADMIN = "admin"
        VIEWER = "viewer"

    tenant = models.ForeignKey(Tenant, on_delete=models.CASCADE, related_name="members")
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=20, choices=Role.choices)

    class Meta:
        db_table = "memberships"
        constraints = [
            models.UniqueConstraint(fields=["tenant", "user"], name="memberships_tenant_user_uniq"),
        ]
