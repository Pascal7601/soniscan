# runner

Executes work in the background: runs scans, checks domain-ownership records, and cleans up stuck
scans. It runs inside **Celery workers** and is the top layer: it imports `scans`, `findings`,
`domains` and the framework-free `scanner` package, and nothing imports it (lower apps enqueue its
tasks by name through `core.tasks.dispatch_on_commit`).

## Breakdown

| File | Responsibility |
|---|---|
| `services.py` | All the logic: `execute_scan()`, `reap_stale_scans()`, `check_domain_verification()`. |
| `tasks.py` | Three thin Celery tasks that call the services. |
| `migrations/0001_initial.py` | Grants for the restricted `scanner_worker` database role. |

Keep `tasks.py` thin: logic belongs in `services.py`, where it is easy to test without Celery.

## The tasks

| Task name | Purpose | Limits |
|---|---|---|
| `runner.run_scan` | Execute one queued scan. | soft 300 s, hard 330 s; retries up to 3 times on database errors |
| `runner.verify_domain` | Look up a domain's verification record. | soft 60 s, hard 90 s; same retry rule |
| `runner.reap_stale_scans` | Fail scans that are stuck. Scheduled by Celery beat every 300 s. | soft 120 s |

All are routed to the `scans` queue (`CELERY_TASK_ROUTES = {"runner.*": ...}`) and use
`acks_late`, so delivery is **at-least-once**. Every task is therefore safe to run twice.

## How a scan runs: `execute_scan()`

Three short database transactions around a network phase that holds **no transaction**, so a slow
DNS lookup never keeps a connection or a row lock open.

```
1. CLAIM    queued -> running   (one conditional UPDATE; returns a job description)
2. RUN      scanner checks      (DNS and CPU only, no database)
3. FINISH   ingest findings + final status + audit event   (one transaction)
```

### Phase 1: claim

`UPDATE scans SET status='running' WHERE id=... AND status='queued'`. If nothing was updated the
scan is already claimed, finished or unknown and the task returns `skipped`. This is what makes a
redelivered message harmless.

If the update trips the database guard (an active scan whose domain verification lapsed after it was
queued), the claim's transaction rolls back and a **fresh** transaction marks the scan `refused` and
audits `scan.refused`.

### Phase 2: run

`scanner.runner.select_checks()` picks passive checks, or all checks for an active scan on a
verified domain; `run_checks()` runs them. Each check is isolated: a check that raises is recorded
as a failure and contributes **no results and no coverage**.

### Phase 3: finish

| What happened | Final status |
|---|---|
| No check failed | `succeeded` |
| Some checks failed, some completed | `partial` (the completed checks' results are saved) |
| Every check failed | `failed` |
| Findings could not be saved (for example a check with no library text) | `failed`, error starts with `ingest:` |

When no check completed, nothing is ingested: nothing can be concluded, so no finding is created or
closed. The scan row gets `finished_at`, `scanner_version` and an internal `error`, and a
`scan.completed` audit event records the counts.

### Results of `execute_scan()`

`succeeded`, `partial`, `failed`, `refused` (the guard rejected it), `skipped` (not queued).

### Unexpected errors

Anything unexpected during the run marks the scan `failed` (audited as `scan.failed` with reason
`execution_error`) and is **re-raised** so Celery logs it.

## The reaper: `reap_stale_scans()`

Fails scans that will never finish:

| Stuck state | After | Recorded reason |
|---|---|---|
| `running` (worker died) | 15 minutes (`STALE_RUNNING_AFTER`) | `worker_lost` |
| `queued` (the job was never delivered, for example broker down) | 15 minutes (`STALE_QUEUED_AFTER`) | `never_started` |

Failed scans do not use the customer's monthly quota, so they can simply try again. To find stuck
scans **across all tenants** the reaper must run as the `scanner_worker` role, which has one extra
read-only policy (below). Run **exactly one** Celery beat process.

## Domain verification: `check_domain_verification()`

Same shape as a scan: read the pending attempt (transaction), look up the DNS TXT record (no
transaction), then complete it (transaction). Outcomes:

| Outcome | Meaning |
|---|---|
| `verified` | The right token was found; the domain is now verified. |
| `not_found` | Record not visible yet; the attempt stays pending so the customer can retry. Audited as `record_not_found`. |
| `dns_error` | The lookup itself failed (timeout, untrusted resolver). Stays pending. Audited as `dns_error`. |
| `expired` | The 7-day attempt ran out. |
| `no_pending` | No pending attempt (or the domain belongs to another organisation). |
| `already_claimed` | Another organisation already holds the verified claim. Audited as `domain.verification_conflict`. |

## The `scanner_worker` database role

Workers do not run as the application role. The migration grants `scanner_worker` only what a scan
needs, and only specific **columns** of the tables it updates:

| Table | Privileges |
|---|---|
| `domains` | `SELECT`; `UPDATE (status, verified_at, verified_method, reverify_due, updated_at)` |
| `domain_verifications` | `SELECT`; `UPDATE (result, checked_at, updated_at)` |
| `scans` | `SELECT`; `UPDATE (status, started_at, finished_at, scanner_version, error, updated_at)` |
| `findings` | `SELECT`, `INSERT`, `UPDATE` |
| `finding_observations` | `SELECT`, `INSERT` |
| `check_definitions`, `scoring_models` | `SELECT` |
| `audit_log` | `INSERT` |

Consequences: a worker cannot turn a passive scan into an active one (`mode` is not updatable),
cannot change a domain's name or owner, cannot delete anything, and cannot read users, memberships
or tenants. One extra policy, `scanner_worker_unfinished`, lets it **read** (not write) scans whose
status is `queued` or `running` in any tenant; every write still happens inside one tenant's
context. The role must exist **before** migrating (`infra/postgres/init.sql`); if it does not, the
migration does nothing.

## Settings

| Setting (env var) | Default | Purpose |
|---|---|---|
| `SCANNER_DNS_SERVERS` | empty (container resolver) | Comma-separated resolvers for scan lookups. Pin public resolvers in production. |
| `SCANNER_DNS_TIMEOUT` | `5.0` | Seconds per DNS lookup. |
| `SCANNER_DNS_CANARY` | `a.root-servers.net` | A name that must resolve; if it does not, the resolver is untrusted and the scan fails. Empty disables it (not recommended). |
| `CELERY_BROKER_URL` (`REDIS_URL`) | `redis://localhost:6379/0` | Broker. |

## Running it

```bash
make worker      # a worker as the scanner_worker role (needs WORKER_DATABASE_URL in .env)
make beat        # the scheduler (exactly one)
make stack       # or the whole stack in containers
```

## Failure modes

| What breaks | What happens |
|---|---|
| Broker down when a scan is requested | The scan stays `queued`; the request succeeds; the reaper fails it after 15 minutes. |
| Worker dies mid-scan | The message is redelivered and skipped (not `queued`); the reaper fails the scan after 15 minutes. |
| Database blip | The task retries with backoff (up to 3 times) when nothing has changed yet. |
| DNS timeout or **hijacked resolver** | The check fails; the scan is `failed` or `partial`; **no finding is created or closed.** |
| Verification lapses after queueing | The database guard refuses the claim; the scan is `refused`. |

## Tests

| File | What it proves |
|---|---|
| `tests/runner/test_execute.py` | The happy path, idempotency, failure handling, the guard, no transaction held during the network phase, hijacked-resolver regression. |
| `tests/runner/test_reaper_and_verify.py` | Reaper rules and quota, and every verification outcome. |
| `tests/runner/test_worker_role.py` | A full scan with only the worker's grants, and everything the role must **not** be able to do. |