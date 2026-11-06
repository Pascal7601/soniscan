# findings

What the scanner found, how serious it is, and what the customer should do about it. Three
responsibilities live here:

1. the **check library**: the plain-language text for every possible finding;
2. the **finding lifecycle**: tracking each issue across scans (new, persisting, fixed, reopened);
3. the **score**: turning open findings into a grade and a "fix this first" list.

Depends on: `scans`, `domains`, `accounts`, `core`, and the framework-free `scanner` package
(`scanner.scoring`). Used by: `runner`.

## Breakdown

| File | Responsibility |
|---|---|
| `models.py` | `CheckDefinition`, `ScoringModel`, `Finding`, `FindingObservation`. |
| `library.py` | Loads, validates and syncs the TOML check library into the database as versions. |
| `library/*.toml` | The customer-facing text, one `[[checks]]` entry per finding type. |
| `management/commands/sync_check_library.py` | `manage.py sync_check_library`, run on every deploy. |
| `services.py` | `ingest_results()` (the lifecycle), `compute_posture()`, `accept_risk()`. |
| `selectors.py` | `current_scoring_model()`, `list_findings()`, `fix_first()`, `get_finding()`. |
| `api/` | `views.py`, `serializers.py`, `urls.py`. |
| `migrations/0001_initial.py` | Tables (generated). |
| `migrations/0002_rls_tenant_consistency_and_privileges.py` | Row-level security, composite foreign keys, and **read-only** privileges on the global tables. |
| `migrations/0003_seed_scoring_model_v1.py` | Seeds scoring model version 1. |

## Data model

### `check_definitions` (global, read-only for the app)

One row per **version** of a check's text. Fields: `check_key` (for example
`EMAIL_DMARC_MISSING`), `version`, `category`, `requires_verification`, `title`, `severity_base`,
`exploitability_base`, `plain_explanation`, `why_it_matters`, `fix_steps` (ordered list), `effort`
(`minutes`, `hours`, `days`), `owner_hint`, `reference_links`, `content_hash`, `is_active`.
Constraints: `checkdef_key_version_uniq`, `checkdef_exploitability_range`.

### `scoring_models` (global, read-only for the app)

Versioned scoring constants (`version`, `params` JSON). The engine reads the **highest version**.
Each observation records which version produced its score.

### `findings`

One row per *issue*, identified by a stable `fingerprint = sha256(check_key | asset)` within a
domain. Holds the **lifecycle**: `status` (`open`, `fixed`, `accepted_risk`, `false_positive`),
first/last seen scan and time, `fixed_at`, `reopened_count`, and the risk-acceptance fields. Also
holds the **latest** `severity`, `exploitability`, `exposure` and `score`. `asset` is plain text
for now (for example `acme.example`); an assets table arrives with active scans.

| Constraint or index | Rule |
|---|---|
| `findings_domain_fp_uniq` | One finding per domain and fingerprint. |
| `findings_id_tenant_uniq` | Target for composite foreign keys. |
| `findings_score_range` | `0 <= score <= 10`. |
| `findings_factors_range` | `exploitability` and `exposure` between 0 and 1. |
| `findings_accepted_needs_reason` | An `accepted_risk` finding must have a reason. |
| `findings_open_ranked_idx`, `findings_domain_status_idx` | Fast "open findings ranked by score". |

### `finding_observations`

The **evidence from one scan** for one finding: the scores at that moment, the raw `evidence` JSON,
and which `check_definition` version and `scoring_model` produced them. Unique per finding and scan
(`observations_finding_scan_uniq`; index `observations_scan_idx`). This is what makes old reports
reproducible.

## The check library

Customer-facing wording lives in `library/*.toml`, not in code, so analysts can improve it in a
pull request without touching Python.

```toml
[[checks]]
key = "EMAIL_DMARC_MONITOR_ONLY"          # UPPER_SNAKE_CASE, unique across all files
category = "email"                        # email, tls, web, subdomain, exposed_service, software, credentials
requires_verification = false             # true for active checks and breach lookups
title = "Fake emails in your company's name are still being delivered"
severity = "medium"                       # critical, high, medium, low, info
exploitability = 0.8                      # 0..1
effort = "minutes"                        # minutes, hours, days
owner = "Whoever manages your domain or email"
explanation = """What is wrong, in everyday language."""
impact = """What it means for the business."""
steps = ["Concrete step one.", "Concrete step two."]
```

Writing rules: no unexplained acronyms, lead with the consequence, steps a non-specialist can
follow.

### What `sync_check_library` does

Run it as the **owner** database role on each deploy (`make migrate` already does). The application
role cannot write these tables.

- **New key** becomes version 1.
- **Changed wording** becomes a **new version**; older versions stay (inactive) so historical
  findings and reports keep the exact text they were shown. Re-wrapping a paragraph does not count
  as a change (whitespace is normalised before hashing).
- **Key removed from the files** is deactivated, never deleted.
- **Invalid file** (missing field, unknown severity or category, duplicate key, bad TOML) aborts the
  whole sync and changes nothing.

Currently shipped keys:

| Key | Severity | Mode | Effort |
|---|---|---|---|
| `EMAIL_DMARC_MISSING` | medium | passive | minutes |
| `EMAIL_DMARC_MONITOR_ONLY` | medium | passive | minutes |
| `EMAIL_DMARC_MULTIPLE` | medium | passive | minutes |
| `SVC_RDP_EXPOSED` | critical | needs verification | hours |

A test guarantees that **every finding key a scanner check can emit has an entry here**, so a check
cannot ship without its explanation.

## The finding lifecycle: `ingest_results()`

Called by the runner after each scan with the scan's results and `covered_keys` (the finding keys
of the checks that **completed**). In one transaction:

| Situation | Result |
|---|---|
| Seen now, never seen before | New finding, `open`. |
| Seen now, already open | Stays open; score and evidence refreshed. |
| Seen now, previously `fixed` | **Reopened** (`reopened_count + 1`). |
| Seen now, risk acceptance has expired | **Reopened**; acceptance details cleared. |
| Seen now, risk accepted and still valid | Stays `accepted_risk`. |
| Not seen now, its check **completed** | Marked `fixed` (also for accepted risks). |
| Not seen now, its check **did not complete** | **Untouched.** A failed or skipped check never closes findings. |

Other guarantees:

- A key with no active library entry raises `UnknownCheck` and **nothing is written**.
- Several results for one check and asset in a scan keep the highest score.
- Each seen finding gets a `FindingObservation` recording the library version and scoring model.
- Only the findings rows are locked (`select_for_update(of=("self",))`), because a plain
  `FOR UPDATE` would also lock the joined library rows, which the application role may not update.

## Scoring

The formulas live in `scanner/scoring.py` (documented in `scanner/README.md`). This app applies them:

- A finding's score is `severity weight x exploitability x exposure`, stored on the finding.
- `compute_posture()` takes only **open** findings (fixed and accepted ones do not count) and
  returns `score` (0 to 100), `grade` (A to F), `total_risk`, `capped_by`, and counts per tier.
- Tiers: score at least 7 is `fix_now`, at least 4 is `fix_this_month`, otherwise `plan_later`.

**To change the scoring constants**, add a new row to `scoring_models` with a higher `version` in a
migration (never edit an existing row, and never edit the frozen copy in migration 0003). Existing
findings keep their stored scores until the next scan re-scores them; each observation records
which version it used.

## Accepting a risk

`accept_risk()` records that the business knowingly accepts a risk. It is **time-boxed** so it is
re-reviewed: the review date must be in the future and at most **365 days** away. A reason is
required, only `open` findings qualify, and the event is audited (`finding.risk_accepted`). When
the date passes, the next scan that still sees the issue reopens it. The API restricts this to
owners and admins.

## API

| Method and path | Purpose | Notes |
|---|---|---|
| `GET /api/v1/domains/{domain_id}/findings/` | List findings. | Query `status`: `open` (default), `fixed`, `accepted_risk`, `false_positive` or `all`. Invalid value: `400`. Each item: `id`, `check_key`, `title`, `asset`, `severity`, `score`, `tier`, `status`, `first_seen_at`, `last_seen_at`, `reopened_count`, `accepted_until`. |
| `GET /api/v1/domains/{domain_id}/posture/` | Overall result. | `score`, `grade`, `total_risk`, `capped_by` (`critical`, `high` or `null`), `open_findings`, `counts_by_tier`. |
| `GET /api/v1/domains/{domain_id}/fix-first/` | Top 5 open findings, ranked. | Ordered by score (highest first), ties broken by lowest effort, then asset. Each item adds `rank`, `plain_explanation`, `why_it_matters`, `fix_steps`, `effort`, `owner_hint`. |
| `POST /api/v1/findings/{finding_id}/accept-risk/` | Accept a risk. | Body: `reason` (10 to 2000 characters) and `until` (future date-time, at most 365 days away). `403` for viewers, `400` for invalid input or a finding that is not open, `404` for another organisation's finding. |

`false_positive` is a valid status and filter, but no endpoint sets it yet.

## Database protections

- Row-level security on `findings` and `finding_observations`.
- Composite foreign keys keep every row inside one organisation:
  `findings_domain_tenant_fk`, `findings_first_scan_tenant_fk`, `findings_last_scan_tenant_fk`,
  `observations_finding_tenant_fk`, `observations_scan_tenant_fk`. The two references to scans use
  `NO ACTION`: a scan that findings point at cannot be deleted on its own, but deleting a whole
  domain still removes its scans and findings in one statement.
- `REVOKE INSERT, UPDATE, DELETE, TRUNCATE` on `check_definitions` and `scoring_models` from the
  application role (skipped if the role does not exist).

## Tests

| File | What it proves |
|---|---|
| `tests/findings/test_ingest.py` | Every lifecycle rule above, risk-acceptance rules, unknown keys, library versions. |
| `tests/findings/test_library.py` | Loading, validation, versioned sync, privileges, and the "every emitted key has text" guard. |
| `tests/findings/test_api.py` | Endpoints, the design-document scoring example end to end, ranking and tie-breaks, roles, isolation. |
| `tests/findings/test_db_rules.py` | Constraints and foreign keys enforced by PostgreSQL itself. |
| `tests/findings/test_end_to_end.py` | Real scanner check to findings to score, across three scans. |
| `tests/scanner/test_scoring.py` | The scoring engine, including the worked example. |

## Adding a new kind of finding

1. Write the check in `backend/scanner/` (see `scanner/README.md`) and list its keys in `emits`.
2. Add an entry per key to `library/*.toml`.
3. `make test`. The guard test fails until step 2 is done.
4. Deploy; `sync_check_library` publishes the new text.