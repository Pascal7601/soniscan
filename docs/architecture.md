# Architecture

```
Browser --> Next.js (same origin) --/api proxy--> Django API --> PostgreSQL (RLS)
                                                     |
                                                     +--> Redis --> Celery workers
                                                                     (scan queue; runs the
                                                                      framework-free scanner)
```

## Key properties

- **Same-origin API proxy.** The browser only talks to Next.js; `/api/*` is rewritten to Django.
  Session cookies stay same-site, no CORS, CSRF protection stays simple.
- **Transaction-scoped tenant context.** One transaction per request (`ATOMIC_REQUESTS`).
  `TenantScopedAPIView` sets `app.current_user` / `app.current_tenant` with `set_config(.., true)`
  after authentication. They disappear when the transaction ends, so they cannot leak across
  pooled connections. Background jobs use `core.tenancy.tenant_context(...)`.
- **Two database roles.** Migrations run as the owner; the application runs as `app_api`
  (non-superuser, no BYPASSRLS), so policies always apply. Scanner workers get a narrower role.
- **Scanner isolation.** `scanner/` has no Django imports. Workers run in containers with no access
  to internal networks, and every probe first passes `scanner/safety.py`.

## Planned apps

`scans` (orchestration, Celery tasks, active-scan guard trigger), `findings` (lifecycle,
observations, check library), `reports` (scoring model, PDF), `billing`.
The target schema is in `docs/db/reference-schema.sql`; Django migrations are the source of truth.
