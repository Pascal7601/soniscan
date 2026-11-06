# domains

The websites a customer wants checked, and **proof that they own them**. Proof matters: active
scans (port scans, service fingerprinting) are only legal and ethical against domains the customer
controls, so ownership verification is the most important control in the product.

Depends on: `accounts`, `core`. Used by: `scans`, `findings`, `runner`.

## Breakdown

| File | Responsibility |
|---|---|
| `models.py` | `Domain`, `DomainVerification`. |
| `services.py` | Validation, plan limits, starting and completing verification, requesting a check. |
| `selectors.py` | `list_domains()`, `get_domain()`. Read-only. |
| `api/views.py` | Domain list/create, start verification, request a verification check. |
| `api/serializers.py` | Request and response shapes. |
| `api/urls.py` | Routes. |
| `migrations/0001_initial.py` | Tables and constraints (generated). |
| `migrations/0002_rls_and_tenant_consistency.py` | Row-level security and the composite foreign key. |

## Data model

### `domains`

| Column | Meaning |
|---|---|
| `fqdn` | Lowercase, normalised host name (for example `acme.example`). |
| `status` | `pending`, `verified`, `expired` or `suspended`. |
| `verified_at`, `verified_method`, `reverify_due` | Set when verified. `verified_method` is `dns_txt` or `http_file` (empty string when not verified). Verification must be repeated before `reverify_due` (90 days). |

| Constraint | Rule it enforces |
|---|---|
| `domains_tenant_fqdn_uniq` | An organisation cannot add the same domain twice. |
| `domains_id_tenant_uniq` | Target for composite foreign keys from child tables. |
| `domains_single_verified_owner` | **Only one organisation can hold a verified claim on a domain.** A partial unique index on `fqdn` where `status = 'verified'`. |
| `domains_fqdn_lowercase` | Stored names are lowercase. |
| `domains_verified_fields_set` | A `verified` domain must have `verified_at`, `verified_method` and `reverify_due`. |

`Domain.is_verified_now()` is true only when `status` is `verified` **and** `reverify_due` is in the
future. Always use it (never the status alone) when deciding whether an active scan may run.

### `domain_verifications`

One row per verification attempt.

| Column | Meaning |
|---|---|
| `method` | `dns_txt` or `http_file`. Only `dns_txt` is checked by the runner today. |
| `token_hash` | SHA-256 of the secret token. **The plaintext token is never stored** and is shown to the user once. |
| `expires_at` | 7 days after the attempt starts. |
| `checked_at` | Time of the last check. |
| `result` | `pending`, `verified`, `failed` or `expired`. A missed check leaves it `pending`; `failed` is reserved and not currently set. |

## How verification works

```
Customer                  API                      Worker (runner)             DNS
  | POST .../verification/ |                            |                        |
  |----------------------->| start_verification()       |                        |
  |<-- record name + value-| stores SHA-256(token)      |                        |
  | adds the TXT record at their DNS provider ...................................>|
  | POST .../verification/check/                        |                        |
  |----------------------->| request_verification_check()-- queue --> verify_domain
  |<------- 202 -----------|                            |-- TXT lookup --------->|
  |                        |                            |<-- values -------------|
  |                        |                            | complete_verification()|
  | GET /api/v1/domains/   |   status is now "verified" |                        |
```

1. **Start.** `start_verification()` makes a random token (`secrets.token_urlsafe(32)`), stores only
   its hash, and the API returns the DNS record to create:
   name `_posture-verify.<fqdn>`, value `posture-verify=<token>`.
2. **Check.** The customer calls the check endpoint. It returns `202` immediately and queues
   `runner.verify_domain`; the worker looks up the TXT record and calls
   `complete_verification()`.
3. **Complete.** Each observed value starting with `posture-verify=` is hashed and compared with the
   stored hash using a constant-time comparison (`hmac.compare_digest`). On a match the domain
   becomes `verified`, and `reverify_due` is set 90 days ahead.

Behaviours worth knowing:

- **A miss does not burn the token.** DNS changes take minutes to propagate, so a failed check
  leaves the attempt `pending` until it expires (7 days) and the customer can simply check again.
- **A DNS error is not a miss.** If the lookup itself fails (timeout, untrusted resolver), the
  attempt stays pending and `domain.verification_check_failed` is audited with `dns_error`.
- **First verified claim wins.** If another organisation already holds a verified claim, completion
  raises `DomainAlreadyClaimed` and the attempt is rejected (and audited as
  `domain.verification_conflict`).
- **Verification lapses.** `reverify_due` passing makes `is_verified_now()` false and the database
  guard in `scans` refuses new active scans. The `status` column is not rewritten automatically
  (a periodic sweeper is a future improvement).

## Services

| Function | What it does |
|---|---|
| `normalise_fqdn(raw)` | Trims, lowercases, removes a trailing dot, converts internationalised names to ASCII (IDNA), rejects IP addresses, single-label names and invalid labels. Raises `InvalidDomain`. |
| `add_domain(tenant_id, fqdn)` | Locks the tenant row, enforces the plan limit (`PLAN_MAX_DOMAINS`: free 1, starter 3, business 10), creates the domain. Raises `QuotaExceeded`, `InvalidDomain`. |
| `start_verification(domain, method, actor_id)` | Creates the attempt, returns `(DomainVerification, plaintext_token)`. |
| `complete_verification(verification, observed_values)` | Pure of network access: compares observed TXT values and updates the domain. Returns `True`/`False`. |
| `request_verification_check(domain, actor_id)` | Audits and queues the worker job. Raises `NoPendingVerification` if there is no unexpired pending attempt. |
| `verification_record_name(domain)` | `_posture-verify.<fqdn>`. |

All rule violations derive from `DomainError`; views translate them into HTTP responses.

## API

| Method and path | Purpose | Responses |
|---|---|---|
| `GET /api/v1/domains/` | List the organisation's domains. | `200` |
| `POST /api/v1/domains/` | Add a domain (`{"fqdn": "acme.example"}`). | `201`; `400` for an invalid name, duplicate or plan limit |
| `POST /api/v1/domains/{domain_id}/verification/` | Start verification. Returns `method`, `record_name`, `record_value` (**shown once**) and `expires_at`. | `201`; `404` |
| `POST /api/v1/domains/{domain_id}/verification/check/` | Ask a worker to check the DNS record. Rate limited to **6 per minute** per user. | `202` queued; `200` already verified; `409` no pending attempt; `404`; `429` |

## Database protections

- Row-level security on `domains` and `domain_verifications` (policy `tenant_isolation`).
- Composite foreign key `domain_verifications_domain_tenant_fk`: a verification can never point at
  another organisation's domain.
- The constraints in the table above, including the one-verified-owner rule.

## Audit events

`domain.verification_started`, `domain.verification_check_requested`, `domain.verified` are written
here; `domain.verification_check_failed` and `domain.verification_conflict` by the runner. See the
catalogue in `apps/core/README.md`.

## Known gaps

- Public-suffix names such as `co.ke` or `com` are not yet rejected (TODO in `normalise_fqdn`).
- The `http_file` method exists in the data model but the runner only checks DNS TXT records.
- No automatic sweeper moves lapsed domains from `verified` to `expired`.

## Tests

| File | What it proves |
|---|---|
| `tests/domains/test_services.py` | Name normalisation, plan limits, token hashing, success/failure/expiry, one claim per domain. |
| `tests/domains/test_verification_check_api.py` | The check endpoint, its responses, rate limit, and that a miss keeps the token usable. |
| `tests/runner/test_reaper_and_verify.py` | The worker side: every verification outcome, including conflicts and DNS errors. |
| `tests/core/test_tenant_isolation.py` | One verified owner per domain; cross-tenant foreign keys rejected. |