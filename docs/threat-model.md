# Threat model

Maintained alongside the design document. Update this file in the same PR that changes a trust
boundary (new external call, new role, new data store, new check type).

| Threat | Mitigation | Where enforced |
|---|---|---|
| Scanning a domain the user does not own | Ownership verification, re-verification, audit log | `apps/domains/services.py`; scan guard trigger (next) |
| Scanner used against internal networks (SSRF) | Block non-public IPs, connect by resolved IP | `scanner/safety.py` |
| Cross-tenant data access | Row-level security, composite FKs, tenant-scoped views | `apps/core/`, `tests/core/` |
| Verification token theft from database | Only SHA-256 hash stored, shown once | `apps/domains/services.py` |
| Two tenants claiming one domain | Partial unique index on verified claims | `apps/domains/models.py` |
| Account takeover | MFA, session hardening (open: identity provider, see ADR-0006) | TBD |

## Open items
- Public-suffix rejection for domain registration (TODO in `normalise_fqdn`).
- Append-only audit log and scan guard trigger arrive with the `scans` app.
