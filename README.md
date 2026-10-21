# Security Posture Scanner

Checks a company's public internet footprint and produces a plain-language "fix this first"
report for SME owners. Django + DRF API, Next.js frontend, PostgreSQL, Celery.

## Repository layout

```
backend/            Django project (API, business logic, migrations)
  config/           Settings (base/local/production/test), URLs, Celery
  apps/             One Django app per business area
    core/           Lowest layer: base models, tenant context, migration helpers
    accounts/       Users, organisations (tenants), memberships, tenant-scoped API base
    domains/        Domains and ownership verification
    scans/          (next) scan orchestration and Celery tasks
    findings/       (next) findings lifecycle, check library
    reports/        (next) scoring and report generation
    billing/        (later)
  scanner/          Framework-free scanning engine: checks, SSRF guard, no Django imports
  tests/            Mirrors the source layout
frontend/           Next.js (App Router, TypeScript)
  src/features/     One folder per business area, mirroring backend/apps
  src/lib/api/      Typed client generated from the backend OpenAPI contract
docs/               Architecture, ADRs, threat model, reference DB schema
infra/              Local Postgres init (roles), later Terraform
```

## Quick start

```bash
cp .env.example .env
make up                                   # Postgres + Redis
python -m venv .venv && . .venv/bin/activate
pip install -e "backend[dev]"
make migrate && make run                  # API on :8000
cd frontend && npm install && npm run dev # UI on :3000
```

## Conventions that keep this maintainable

1. **Layers inside each Django app.** `models.py` (data), `selectors.py` (reads), `services.py`
   (writes and business rules), `api/` (HTTP only). Views never contain business logic.
2. **The scanner is framework-free.** Checks are pure functions plus a thin class; DNS and network
   access are injected. Enforced in CI by import-linter.
3. **Tenant isolation lives in the database.** Every tenant-owned table gets row-level security
   and a composite foreign key through helpers in `apps/core/db.py`, plus a test in
   `tests/core/test_tenant_isolation.py`. Every API view extends `TenantScopedAPIView`.
4. **One API contract.** Backend serializers produce `backend/openapi.yaml`; the frontend client
   types are generated from it. CI fails if either is stale (`make api-check`).
5. **Decisions are written down.** Significant choices get an ADR in `docs/adr/`.
6. **Schema changes are migrations.** Never edit the database by hand. Security features Django
   cannot express (RLS, composite FKs, triggers) go in reviewed hand-written migrations.

## Quality gates

`make check` runs what CI runs: ruff (lint and format), import-linter (architecture),
mypy and tsc (types), pytest and vitest. CI also verifies there is no model/migration drift,
no stale API contract, and audits dependencies.

## Adding a feature (checklist)

1. New table? Model extends `TenantOwnedModel`, migration enables RLS, test proves isolation.
2. New scanner check? Add to `scanner/checks/`, mark passive or verified-only, unit-test the pure
   evaluation function, add its text to the check library.
3. New endpoint? View extends `TenantScopedAPIView`, logic in `services.py`, run `make api-schema`.
4. Update `docs/threat-model.md` if a trust boundary changed.
