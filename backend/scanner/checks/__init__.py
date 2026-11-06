"""Importing this package registers every check. Add new check modules here."""

from . import dkim, email_auth, spf, web_headers, web_tls  # noqa: F401