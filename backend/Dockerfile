# syntax=docker/dockerfile:1.7
# Build context: ./backend
ARG PYTHON_VERSION=3.12

# ---------- builder: install locked, hash-verified dependencies into a virtualenv ----------
FROM python:${PYTHON_VERSION}-slim AS builder
ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
WORKDIR /build
COPY requirements/base.txt requirements/base.txt
# --require-hashes: refuse anything not pinned to a known artifact hash (supply-chain safety)
RUN pip install --require-hashes -r requirements/base.txt

# ---------- runtime: small image, non-root user, no build tools ----------
FROM python:${PYTHON_VERSION}-slim AS runtime
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PATH="/opt/venv/bin:$PATH" \
    DJANGO_SETTINGS_MODULE=config.settings.production \
    WEB_CONCURRENCY=3

RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --home-dir /app --shell /usr/sbin/nologin app

COPY --from=builder /opt/venv /opt/venv
WORKDIR /app
COPY --chown=app:app . /app

# Collect static files at build time. These values exist only for this command; the real
# secret and hosts are injected at runtime and never baked into the image.
RUN DJANGO_SECRET_KEY=build-time-only DJANGO_ALLOWED_HOSTS=build \
    python manage.py collectstatic --noinput \
 && chown -R app:app /app/staticfiles

USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "docker/healthcheck.py"]

# Override the command to run other roles from the same image, e.g. the Celery worker:
#   celery -A config worker -l info -Q celery,scans
CMD ["gunicorn", "config.wsgi:application", "--bind", "0.0.0.0:8000", "--access-logfile", "-", "--timeout", "30"]