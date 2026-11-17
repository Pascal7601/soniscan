"""Authentication side effects: the first organisation, the audit trail, and `mfa_enabled`.

Connected in AccountsConfig.ready(). Every handler is small on purpose; the rules live in
services.py and apps/core/audit.py.
"""

from allauth.account.signals import (
    email_confirmed,
    password_changed,
    password_reset,
    user_signed_up,
)
from allauth.mfa.models import Authenticator
from allauth.mfa.signals import authenticator_added, authenticator_removed, authenticator_reset
from django.contrib.auth.signals import user_logged_in, user_logged_out, user_login_failed
from django.db.models.signals import post_delete, post_save
from django.dispatch import receiver

from apps.core import audit

from . import services
from .models import User


def _meta(request) -> dict:
    return audit.request_meta(request) if request is not None else {}


# ---- sign-up -------------------------------------------------------------------------------------


@receiver(user_signed_up)
def on_signed_up(sender, request, user, **kwargs) -> None:
    # Covers social sign-up (no form, so no organisation name yet) and is a no-op for password
    # sign-up, where SignupForm.signup() has already created the organisation.
    tenant = services.ensure_organisation(user=user)
    provider = kwargs["sociallogin"].account.provider if kwargs.get("sociallogin") else "password"
    audit.record(
        action="auth.signed_up",
        actor_id=user.id,
        tenant_id=tenant.id,
        target_type="user",
        target_id=user.id,
        metadata={"method": provider},
        **_meta(request),
    )


# ---- sign-in and account events --------------------------------------------------------------------


@receiver(user_logged_in)
def on_login(sender, request, user, **kwargs) -> None:
    audit.record(
        action="auth.login",
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        **_meta(request),
    )


@receiver(user_logged_out)
def on_logout(sender, request, user, **kwargs) -> None:
    if user is not None:
        audit.record(
            action="auth.logout",
            actor_id=user.id,
            target_type="user",
            target_id=user.id,
            **_meta(request),
        )


@receiver(user_login_failed)
def on_login_failed(sender, credentials, request=None, **kwargs) -> None:
    # `credentials` has the password already scrubbed by Django; only the email is kept.
    email = str(credentials.get("email") or credentials.get("username") or "")[:254].lower()
    audit.record(
        action="auth.login_failed",
        actor_id=None,
        metadata={"email": email},
        **_meta(request),
    )


@receiver(password_changed)
def on_password_changed(sender, request, user, **kwargs) -> None:
    audit.record(
        action="auth.password_changed",
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        **_meta(request),
    )


@receiver(password_reset)
def on_password_reset(sender, request, user, **kwargs) -> None:
    audit.record(
        action="auth.password_reset",
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        **_meta(request),
    )


@receiver(email_confirmed)
def on_email_confirmed(sender, request, email_address, **kwargs) -> None:
    audit.record(
        action="auth.email_confirmed",
        actor_id=email_address.user_id,
        target_type="user",
        target_id=email_address.user_id,
        **_meta(request),
    )


# ---- multi-factor authentication -----------------------------------------------------------------


@receiver(authenticator_added)
def on_mfa_added(sender, request, user, authenticator, **kwargs) -> None:
    audit.record(
        action="auth.mfa_added",
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        metadata={"type": authenticator.type},
        **_meta(request),
    )


@receiver(authenticator_removed)
def on_mfa_removed(sender, request, user, authenticator, **kwargs) -> None:
    audit.record(
        action="auth.mfa_removed",
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        metadata={"type": authenticator.type},
        **_meta(request),
    )


@receiver(authenticator_reset)
def on_mfa_reset(sender, request, user, authenticator, **kwargs) -> None:
    audit.record(
        action="auth.mfa_reset",
        actor_id=user.id,
        target_type="user",
        target_id=user.id,
        metadata={"type": authenticator.type},
        **_meta(request),
    )


@receiver([post_save, post_delete], sender=Authenticator)
def sync_mfa_flag(sender, instance, **kwargs) -> None:
    """users.mfa_enabled is true while the user has a real second factor (an authenticator app or a
    passkey). Recovery codes alone do not count. Derived from the rows, so it cannot drift."""
    has_second_factor = (
        Authenticator.objects.filter(user_id=instance.user_id)
        .exclude(type=Authenticator.Type.RECOVERY_CODES)
        .exists()
    )
    User.objects.filter(pk=instance.user_id).update(mfa_enabled=has_second_factor)