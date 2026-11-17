from django.apps import AppConfig
from django.db import connections
from django.db.models.signals import post_migrate


def grant_sequence_access(sender, using="default", **kwargs) -> None:
    """The restricted `app_api` role gets table rights by default (infra/postgres/init.sql) but not
    sequence rights. Third-party apps such as django-allauth use integer keys, so after every
    migration make sure the API role can use their sequences. Idempotent; skipped when the role
    does not exist (for example a plain developer database)."""
    with connections[using].cursor() as cursor:
        cursor.execute("SELECT 1 FROM pg_roles WHERE rolname = 'app_api'")
        if cursor.fetchone():
            cursor.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO app_api")


class AccountsConfig(AppConfig):
    name = "apps.accounts"
    label = "accounts"

    def ready(self) -> None:
        from . import signals  # noqa: F401  (connects the receivers)

        post_migrate.connect(grant_sequence_access, sender=self)