from django.core.exceptions import ImproperlyConfigured

from .base import *  # noqa: F403

if not SECRET_KEY:  # noqa: F405
    raise ImproperlyConfigured("DJANGO_SECRET_KEY must be set in production")
if not ALLOWED_HOSTS:  # noqa: F405
    raise ImproperlyConfigured("DJANGO_ALLOWED_HOSTS must be set in production")

SECURE_SSL_REDIRECT = True
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
if EMAIL_BACKEND.endswith("console.EmailBackend"):  # noqa: F405
    raise ImproperlyConfigured("EMAIL_URL must be set in production (sign-up sends email)")

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"