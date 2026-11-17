"""Hooks that bend django-allauth to this project's rules (see docs/adr/0006-authentication.md)."""

from allauth.account.adapter import DefaultAccountAdapter
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.conf import settings


class AccountAdapter(DefaultAccountAdapter):
    def is_open_for_signup(self, request) -> bool:
        return bool(settings.SIGNUP_OPEN)

    def clean_email(self, email: str) -> str:
        # users.email must be lowercase (database constraint users_email_lowercase).
        return super().clean_email(email).strip().lower()


class SocialAccountAdapter(DefaultSocialAccountAdapter):
    def is_open_for_signup(self, request, sociallogin) -> bool:
        return bool(settings.SIGNUP_OPEN)

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        user.email = (user.email or "").strip().lower()
        if not user.display_name:
            full = data.get("name") or " ".join(
                part for part in (data.get("first_name"), data.get("last_name")) if part
            )
            user.display_name = (full or "").strip()[:200]
        return user