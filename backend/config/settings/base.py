"""Settings shared by every environment. Environment-specific files only override."""

from pathlib import Path

import environ

BASE_DIR = Path(__file__).resolve().parent.parent.parent
env = environ.Env()
environ.Env.read_env(BASE_DIR.parent / ".env")

SECRET_KEY = env("DJANGO_SECRET_KEY", default="")
DEBUG = False
ALLOWED_HOSTS: list[str] = env.list("DJANGO_ALLOWED_HOSTS", default=[])

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "django.contrib.postgres",
    "rest_framework",
    "drf_spectacular",
    "allauth",
    "allauth.account",
    "allauth.headless",
    "allauth.mfa",
    "allauth.socialaccount",
    "apps.core",
    "apps.accounts",
    "apps.domains",
    "apps.scans",
    "apps.findings",
    "apps.reports",
    "apps.runner",
    
]

AUTH_USER_MODEL = "accounts.User"

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "allauth.account.middleware.AccountMiddleware",
]

ROOT_URLCONF = "config.urls"
WSGI_APPLICATION = "config.wsgi.application"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ]
        },
    }
]

# One transaction per request. Tenant context is set with transaction-local settings
# (see apps/core/tenancy.py), so it can never leak between requests on a pooled connection.
DATABASES = {
    "default": {
        **env.db("DATABASE_URL", default="postgres://app_api:app_api_dev@localhost:5432/posture"),
        "ATOMIC_REQUESTS": True,
    }
}
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
        "OPTIONS": {"min_length": 12},
    },
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True
STATIC_URL = "static/"

SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
CSRF_COOKIE_SAMESITE = "Lax"
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = "DENY"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": ["rest_framework.authentication.SessionAuthentication"],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.UserRateThrottle"],
    "DEFAULT_THROTTLE_RATES": {
        "user": "120/min",
        "verification_check": "6/min",
        "report_generate": "20/hour",
        "report_download": "60/hour",
    },
}

SPECTACULAR_SETTINGS = {
    "TITLE": "Security Posture Scanner API",
    "VERSION": "0.1.0",
    "SERVE_INCLUDE_SCHEMA": False,
    "COMPONENT_SPLIT_REQUEST": True,
}

CELERY_BROKER_URL = env("REDIS_URL", default="redis://localhost:6379/0")
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_TIME_LIMIT = 600
CELERY_TASK_ROUTES = {"runner.*": {"queue": "scans"}}
CELERY_BEAT_SCHEDULE = {
    "reap-stale-scans": {"task": "runner.reap_stale_scans", "schedule": 300.0},
}

# DNS servers for scanner lookups. Empty = the container's resolver; set explicit public resolvers
# in production so results do not depend on an internal resolver.
SCANNER_DNS_SERVERS = env.list("SCANNER_DNS_SERVERS", default=[])
SCANNER_DNS_TIMEOUT = env.float("SCANNER_DNS_TIMEOUT", default=5.0)
# Seconds allowed for each TLS handshake and web request a check makes to a customer site.
SCANNER_NET_TIMEOUT = env.float("SCANNER_NET_TIMEOUT", default=5.0)
# A name that must resolve; if it does not, the resolver is untrusted and scans fail instead of
# reporting false findings. Set to an empty string to disable (not recommended).
SCANNER_DNS_CANARY = env("SCANNER_DNS_CANARY", default="a.root-servers.net")

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": "INFO"},
}

# ---- Authentication (docs/adr/0006-authentication.md) ----------------------------------------
FRONTEND_URL = env("FRONTEND_URL", default="http://localhost:3000").rstrip("/")
# The browser app calls the API through its own origin, so Django must trust that origin for POSTs.
CSRF_TRUSTED_ORIGINS = env.list("CSRF_TRUSTED_ORIGINS", default=[FRONTEND_URL])
SIGNUP_OPEN = env.bool("SIGNUP_OPEN", default=True)  # false = invitation-only / private beta

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "allauth.account.auth_backends.AuthenticationBackend",
]
SESSION_COOKIE_AGE = 60 * 60 * 24 * 7
PASSWORD_RESET_TIMEOUT = 60 * 60  # reset links last one hour

ACCOUNT_ADAPTER = "apps.accounts.adapters.AccountAdapter"
SOCIALACCOUNT_ADAPTER = "apps.accounts.adapters.SocialAccountAdapter"
ACCOUNT_SIGNUP_FORM_CLASS = "apps.accounts.forms.SignupForm"
ACCOUNT_USER_MODEL_USERNAME_FIELD = None  # users sign in with their email
ACCOUNT_LOGIN_METHODS = {"email"}
ACCOUNT_SIGNUP_FIELDS = ["email*", "password1*"]
ACCOUNT_EMAIL_VERIFICATION = "mandatory"  # no sign-in before the email address is confirmed
ACCOUNT_EMAIL_NOTIFICATIONS = True  # "your password / MFA changed" emails
ACCOUNT_EMAIL_SUBJECT_PREFIX = ""
ACCOUNT_REAUTHENTICATION_REQUIRED = True  # sensitive changes ask for the password again
ACCOUNT_SESSION_REMEMBER = True

# API-only: the browser app owns every screen; links in emails point at it.
HEADLESS_ONLY = True
HEADLESS_CLIENTS = ["browser"]
HEADLESS_FRONTEND_URLS = {
    "account_confirm_email": f"{FRONTEND_URL}/verify-email/{{key}}",
    "account_reset_password": f"{FRONTEND_URL}/forgot-password",
    "account_reset_password_from_key": f"{FRONTEND_URL}/reset-password/{{key}}",
    "account_signup": f"{FRONTEND_URL}/signup",
    "socialaccount_login_error": f"{FRONTEND_URL}/login?error=social",
}

MFA_SUPPORTED_TYPES = ["totp", "recovery_codes"]  # authenticator app + backup codes
MFA_TOTP_ISSUER = "Security Posture Scanner"

# Social sign-in. A provider is switched on only when both of its variables are set.
SOCIALACCOUNT_PROVIDERS: dict[str, dict] = {}
for _provider, _prefix in {"google": "GOOGLE", "microsoft": "MICROSOFT"}.items():
    _client_id = env(f"{_prefix}_CLIENT_ID", default="")
    _secret = env(f"{_prefix}_CLIENT_SECRET", default="")
    if _client_id and _secret:
        INSTALLED_APPS.append(f"allauth.socialaccount.providers.{_provider}")
        SOCIALACCOUNT_PROVIDERS[_provider] = {"APPS": [{"client_id": _client_id, "secret": _secret}]}
SOCIALACCOUNT_AUTO_SIGNUP = True
SOCIALACCOUNT_EMAIL_AUTHENTICATION = False  # never sign someone into an existing account by email match
SOCIALACCOUNT_LOGIN_ON_GET = False
SOCIALACCOUNT_STORE_TOKENS = False

# Rate limits (login, sign-up, reset) use the cache and the client address, so both must be right.
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": env("REDIS_URL", default="redis://localhost:6379/0"),
    }
}
# How many reverse proxies sit in front of Django (0 = none). Needed so limits apply per person.
ALLAUTH_TRUSTED_PROXY_COUNT = env.int("TRUSTED_PROXY_COUNT", default=0)

EMAIL_CONFIG = env.email_url("EMAIL_URL", default="consolemail://")
vars().update(EMAIL_CONFIG)
DEFAULT_FROM_EMAIL = env("DEFAULT_FROM_EMAIL", default="Security Posture Scanner <no-reply@localhost>")