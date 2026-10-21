from .base import *  # noqa: F403

SECRET_KEY = "test-only-key"  # noqa: S105
ALLOWED_HOSTS = ["testserver", "localhost"]
PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]
