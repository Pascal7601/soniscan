# accounts

Who is using the system and which organisation they act for: users, organisations (*tenants*),
the memberships linking them, and the API base class that turns a request into a tenant context.

Depends on: `core`. Used by: every other app.

## Breakdown

| File | Responsibility |
|---|---|
| `models.py` | `Tenant`, `User`, `UserManager`, `Membership`. |
| `services.py` | `create_tenant_with_owner()`: the one moment a tenant has no context yet. |
| `selectors.py` | `memberships_for_user()`: read-only query. |
| `api/base.py` | `TenantScopedAPIView`: the base class **every authenticated API view extends**. |
| `api/views.py` | `MeView`: `GET /api/v1/me/`. |
| `api/serializers.py` | `MeSerializer`, `MembershipSerializer`. |
| `admin.py` | Registers the three models in the Django admin. |
| `migrations/0001_initial.py` | Tables (generated). |
| `migrations/0002_memberships_rls.py` | Row-level security for `memberships` (custom policy). |

## Data model

| Table | Columns that matter | Notes |
|---|---|---|
| `tenants` | `name`, `plan` (`free`, `starter`, `business`), `status` (`active`, `suspended`, `closed`), `deleted_at` | Global table, **no row-level security** (needed to create an organisation before it has a context). |
| `users` | `email` (unique), `display_name`, `mfa_enabled`, `is_active`, `is_staff` | Global table. Login field is `email`. Constraint `users_email_lowercase` forces stored emails to be lowercase; `UserManager.create_user` lowercases for you. No passwords of third parties are stored; authentication design is open (see below). |
| `memberships` | `tenant`, `user`, `role` (`owner`, `admin`, `viewer`) | Unique per tenant and user (`memberships_tenant_user_uniq`). Row-level security with a custom policy. |

All three use UUID primary keys (from `core.BaseModel`).

## How a request becomes a tenant context

`TenantScopedAPIView` overrides DRF's `perform_authentication`. After DRF has authenticated the
caller, it:

1. activates the **user** context, so the caller can read their own memberships;
2. unless the view sets `require_tenant = False`, works out **which organisation** they act for;
3. activates the **tenant** context, so every query in the view is isolated;
4. sets `request.tenant_id` and `request.membership` for the view to use.

Choosing the organisation:

| Situation | Result |
|---|---|
| `X-Tenant-ID` header is not a UUID | `400` |
| Header names an organisation the user does not belong to | `403` |
| Header names one of their organisations | that organisation is used |
| No header, user belongs to exactly one organisation | that organisation is used |
| No header, user belongs to several (or none) | `400` ("`X-Tenant-ID` header is required.") |
| Not authenticated | rejected by DRF's `IsAuthenticated` |

```python
class WidgetListView(TenantScopedAPIView):          # tenant-scoped (the default)
    def get(self, request):
        widgets = selectors.list_widgets(tenant_id=request.tenant_id)
        ...

class MeView(TenantScopedAPIView):                  # user-level, no tenant needed
    require_tenant = False
```

## Row-level security on `memberships`

Standard tables use one policy (`tenant_id = current_tenant()`). `memberships` has a custom policy,
`memberships_access`, because a user must discover *which* organisations they belong to **before**
choosing one:

- `USING (tenant_id = current_tenant() OR user_id = current_app_user())`: read your own rows, or
  any row of the active tenant.
- `WITH CHECK (tenant_id = current_tenant())`: writing requires the tenant context.

## API

| Method and path | Purpose | Response |
|---|---|---|
| `GET /api/v1/me/` | The signed-in user and their memberships. | `id`, `email`, `display_name`, `memberships[]` (`tenant_id`, `tenant_name`, `role`) |

## Services

`create_tenant_with_owner(owner=user, name="Acme Ltd") -> Tenant` creates the organisation, then
activates its context before creating the owner membership. Without that second step the
membership insert would be rejected by row-level security.

## Roles

| Role | Can |
|---|---|
| `owner` | everything, including accepting risks (`findings` app) |
| `admin` | same as owner for the features that exist today |
| `viewer` | read-only; cannot accept risks |

Role checks live in the views that need them (for example
`findings/api/views.py::FindingAcceptRiskView`), using `request.membership.role`.

## Plans

`Tenant.plan` selects limits, but the limits themselves live next to the rules that use them, as
plain dictionaries: `domains/services.py` (`PLAN_MAX_DOMAINS`) and `scans/services.py`
(`PLAN_MAX_SCANS_PER_MONTH`, `PLAN_ALLOWS_ACTIVE`). A `plans` table is a possible later refactor.

## Open decisions

- **Authentication** (sign-up, login, password reset, MFA, social login) is not built. See
  `docs/adr/0006-authentication-open.md`. Today the Django session and the admin login work.
- **Django admin** runs without a tenant context, so under the restricted `app_api` role tenant
  tables look empty there. Support tooling must use a deliberate, audited path.

## Tests

| File | What it proves |
|---|---|
| `tests/accounts/test_api.py` | `/me/`, the tenant-resolution table above, and the domain flow through the API. |
| `tests/core/test_tenant_isolation.py` | A user sees their own memberships before choosing a tenant. |
| `tests/core/test_api_under_rls.py` | `create_tenant_with_owner` works under the restricted role. |

## Extending

- New authenticated endpoint: extend `TenantScopedAPIView`, put logic in a `services.py`, reads in
  a `selectors.py`, and never filter by anything other than `request.tenant_id`.
- New role: add it to `Membership.Role`, create a migration, and check it where the action happens.