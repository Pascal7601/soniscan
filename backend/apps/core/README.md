# core

The lowest layer. Building blocks every other app relies on; it contains **no business rules** and
imports no other app (enforced by the `app-layers` contract in `backend/.importlinter`).

It solves three problems once, so no other app has to:

1. **Tenant isolation context**: telling PostgreSQL which organisation a transaction acts for.
2. **The audit trail**: an append-only record of security-relevant events.
3. **Queue dispatch**: sending a Celery job only after the database transaction commits.

## Breakdown

| File | Responsibility |
|---|---|
| `models.py` | `BaseModel` (UUID primary key, `created_at`, `updated_at`), `TenantOwnedModel` (adds a `tenant` foreign key), and the `AuditLog` model. |
| `tenancy.py` | `activate()` and `tenant_context()`: set the database tenant/user context for the current transaction. |
| `db.py` | Migration helpers: `enable_tenant_rls()` and `composite_tenant_fk()`. |
| `audit.py` | `record()` writes an audit event; `request_meta()` extracts IP and user agent from a request. |
| `tasks.py` | `dispatch_on_commit()`: enqueue a Celery task by name after the transaction commits. |
| `migrations/0001_initial.py` | Creates the SQL functions `current_tenant()` and `current_app_user()`. |
| `migrations/0002_audit_log.py` | Creates the `audit_log` table (generated). |
| `migrations/0003_audit_log_append_only_and_rls.py` | Makes `audit_log` append-only and adds its row-level security policies. |

## How tenant isolation works

Every customer organisation is a *tenant*. Isolation is enforced **by the database**, not only by
application code, so a forgotten `.filter(tenant=...)` cannot become a data breach.

```
request (authenticated)
  -> TenantScopedAPIView (accounts) resolves which organisation the caller acts for
  -> tenancy.activate(user_id=..., tenant_id=...)
       SELECT set_config('app.current_user',   '<uuid>', true)   -- true = this transaction only
       SELECT set_config('app.current_tenant', '<uuid>', true)
  -> SQL functions current_tenant() / current_app_user() read those settings
  -> row-level security policies compare  tenant_id = current_tenant()
  -> any query now only sees, and can only write, that tenant's rows
```

Key properties:

- **Fails closed.** If nothing is set, `current_tenant()` returns `NULL`, the comparison is never
  true, and queries return zero rows.
- **Cannot leak between requests.** The settings are transaction-local, so they disappear when the
  transaction ends, even on a pooled connection. `ATOMIC_REQUESTS = True` guarantees every request
  has a transaction; `activate()` raises `RuntimeError` if called outside one.
- **Applies to the owner too.** Tables use `FORCE ROW LEVEL SECURITY`. Only superusers and roles
  with `BYPASSRLS` skip it, which is why the application connects as the non-superuser `app_api`
  role (see `infra/postgres/init.sql`).
- **Outside HTTP requests** (Celery tasks, management commands) use the context manager:

```python
from apps.core.tenancy import tenant_context

with tenant_context(tenant_id):          # opens a transaction and sets the context
    ...                                  # queries here see only this tenant
```

## Migration helpers (`db.py`)

Django cannot express row-level security or composite foreign keys, so these helpers produce the
SQL for hand-written migrations.

```python
from apps.core.db import composite_tenant_fk, enable_tenant_rls

operations = [
    enable_tenant_rls("widgets"),                     # ENABLE + FORCE RLS, policy "tenant_isolation"
    composite_tenant_fk(                              # child row cannot point at another tenant's parent
        table="widget_parts", column="widget_id",
        parent_table="widgets", name="widget_parts_widget_tenant_fk",
    ),
]
```

- `enable_tenant_rls(table)` creates policy `tenant_isolation` with
  `USING (tenant_id = current_tenant()) WITH CHECK (tenant_id = current_tenant())`.
- `composite_tenant_fk(...)` adds `FOREIGN KEY (column, tenant_id) REFERENCES parent (id, tenant_id)`.
  The parent table needs `UNIQUE (id, tenant_id)`. Pass `on_delete="NO ACTION"` for references that
  must block deleting the parent but still allow a cascade that removes both in one statement
  (used for findings pointing at scans). Allowed values: `CASCADE`, `NO ACTION`, `RESTRICT`.

## The audit trail

`audit.record(action=..., ...)` inserts one row into `audit_log`.

```python
audit.record(
    action="scan.requested", actor_id=user.id, tenant_id=tenant.id,
    target_type="scan", target_id=scan.id, metadata={"mode": "passive"},
)
```

How it behaves:

- **Append-only, enforced by the database.** Triggers `audit_log_no_update_delete` and
  `audit_log_no_truncate` raise `audit_log is append-only` for any `UPDATE`, `DELETE` or `TRUNCATE`,
  even from the table owner or a superuser.
- **Row-level security.** Policy `audit_read_own` lets a tenant read only its own events;
  `audit_append` lets the application and workers insert.
- **Plain `INSERT`, no `RETURNING`.** With row-level security, `RETURNING` would require the new row
  to also pass the SELECT policy, which system events (`tenant_id` is `NULL`) deliberately do not.
- **`tenant_id` is not a foreign key**, so history outlives the organisation it describes.
- `request_meta(request)` returns `ip` and `user_agent`. Behind a reverse proxy, configure the proxy
  so `REMOTE_ADDR` is the real client address; never trust a client-supplied `X-Forwarded-For`.

> **Rule: never write an audit row in a block that is about to raise.** Raising inside
> `@transaction.atomic` rolls the audit row back, and DRF also rolls the request transaction back
> when an exception reaches its handler. To keep a "refused" event, record it and then **return a
> normal response** (see `scans/api/views.py`) or write it in a fresh transaction (see
> `runner/services.py::_claim`).

### Audit event catalogue

Every `audit.record(action=...)` call in the codebase must appear in this table. A test
(`tests/test_docs.py`) fails if one is missing.

| Action | Written by | Actor | Metadata |
|---|---|---|---|
| `domain.verification_started` | `domains.services.start_verification` | user | `method` |
| `domain.verification_check_requested` | `domains.services.request_verification_check` | user | none |
| `domain.verified` | `domains.services.complete_verification` | system | `method`, `fqdn` |
| `domain.verification_check_failed` | `runner.services.check_domain_verification` | scanner | `reason`: `dns_error` or `record_not_found` |
| `domain.verification_conflict` | `runner.services.check_domain_verification` | scanner | none (another organisation already holds the verified claim) |
| `scan.requested` | `scans.services.request_scan` | user | `mode`, `domain`, `trigger` |
| `scan.refused` | `scans/api/views.py` (request refused) or `runner.services._claim` (guard refused) | user or scanner | `reason`, and `mode` when written by the API |
| `scan.completed` | `runner.services._finish` | scanner | `status`, `mode`, `findings` (`new`, `reopened`, `persisting`, `fixed`, or `null`), `failed_checks` |
| `scan.failed` | `runner.services._mark_unfinished` | scanner | `reason`: `execution_error`, `worker_lost` or `never_started` |
| `finding.risk_accepted` | `findings.services.accept_risk` | user | `check_key`, `asset`, `severity`, `until`, `reason` |

## Queue dispatch (`tasks.py`)

Lower layers (`scans`, `domains`) must not import the app that implements a task (`runner`, a
higher layer), so they enqueue by **task name**:

```python
from apps.core.tasks import dispatch_on_commit
dispatch_on_commit("runner.run_scan", str(tenant_id), str(scan_id))
```

- The message is sent only **after the transaction commits**, so a worker can never receive a job
  for a row that does not exist yet.
- If the broker is unreachable at that moment the error is **logged, not raised**. The row stays
  committed, the API request still succeeds, and `runner.reap_stale_scans` later fails a scan that
  never started so the user can retry.

## Database objects owned by this app

| Kind | Name |
|---|---|
| Table | `audit_log` (index `audit_log_tenant_time_idx`) |
| SQL functions | `current_tenant()`, `current_app_user()`, `audit_log_reject_change()` |
| Triggers | `audit_log_no_update_delete`, `audit_log_no_truncate` |
| Policies | `audit_read_own` (SELECT), `audit_append` (INSERT) |

## Tests

| File | What it proves |
|---|---|
| `tests/core/test_tenant_isolation.py` | RLS fails closed, tenants see only their rows, cross-tenant writes are rejected, composite foreign keys hold. |
| `tests/core/test_api_under_rls.py` | The real API, running as the restricted `app_api` role, never exposes another tenant's data. |
| `tests/core/test_audit.py` | Events are written, the log cannot be updated/deleted/truncated, tenants read only their own events. |
| `tests/core/test_health.py` | `/healthz/` never touches the database; `/readyz/` does. |

Tests run as a superuser by default, which **bypasses** row-level security. Any test that must
prove isolation calls the `app_api_role` fixture (`tests/conftest.py`) *after* seeding its data.

## Rules for other apps

- A new tenant-owned model extends `TenantOwnedModel`, its migration calls `enable_tenant_rls()`,
  and a test proves another tenant cannot see it.
- Child tables get a composite foreign key to their parent with `composite_tenant_fk()`.
- Every security-relevant action calls `audit.record()` and gets a row in the catalogue above.
- Use `tenant_context()` in any code that runs outside a request.