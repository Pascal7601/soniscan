# Soni frontend

Next.js App Router + TypeScript client for the Django REST API.

## Local setup

```bash
cp .env.example .env.local
npm install
npm run dev
```

Set `BACKEND_URL` to the Django server address in `.env.local` (defaults to `http://127.0.0.1:8000`). Next.js proxies `/api/*` to Django so browser requests remain same-origin and Django session/CSRF cookies work without enabling permissive cross-origin credentials.

## Implemented routes

- `/` — posture overview, selected-domain posture, fix-first list and recent scans.
- `/domains` — add domains, start DNS TXT verification, copy the one-time TXT value and queue a verification check.
- `/scans` and `/scans/[id]` — queue passive/active scans and inspect lifecycle states.
- `/findings` and `/findings/[id]` — filter findings, inspect explanations and remediation, record risk acceptance for owner/admin memberships.
- `/reports` — generate reports and download PDFs.
- `/settings` — account and current organisation membership information.

## Authentication and tenancy

The backend currently protects the API with Django `SessionAuthentication`; sign-up/login/password reset/MFA are not exposed as a decided frontend contract. This UI therefore does not fabricate a login flow. The user must have a valid Django session before calling protected API endpoints. The app requests `/api/v1/auth/csrf/`, reads Django's CSRF cookie for unsafe requests, and sends the selected tenant in `X-Tenant-ID`.

## API types

`src/lib/api/types.ts` contains the app-facing interfaces used by the screens. The OpenAPI contract is `../backend/openapi.yaml`; run `npm run api:types` to refresh the generated raw schema declaration at `src/lib/api/schema.d.ts`.
