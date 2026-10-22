from django.core.management.base import BaseCommand, CommandError

from apps.findings.library import LibraryError, sync_check_library


class Command(BaseCommand):
    help = "Sync the check library (TOML files) into the database as versioned definitions."

    def handle(self, *args, **options):
        try:
            result = sync_check_library()
        except LibraryError as exc:
            raise CommandError(str(exc)) from exc
        self.stdout.write(
            f"created={len(result.created)} updated={len(result.updated)} "
            f"retired={len(result.retired)} unchanged={result.unchanged}"
        )