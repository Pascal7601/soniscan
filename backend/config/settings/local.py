from .base import *  # noqa: F403
from .base import SECRET_KEY as _BASE_SECRET_KEY

DEBUG = True
ALLOWED_HOSTS = ["localhost", "127.0.0.1"]
SECRET_KEY = _BASE_SECRET_KEY or "insecure-local-development-key"
EMAIL_BACKEND = "django.core.mail.backends.console.EmailBackend"
