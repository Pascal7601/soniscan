# ADR-0001: Monorepo with Django API and Next.js frontend

Status: accepted
Date: 2026-10-19

## Context
Two-person founding team; backend and frontend change together (API contract, features).

## Decision
One repository: `backend/` (Django + DRF + Celery), `frontend/` (Next.js), shared docs and CI.
The frontend proxies `/api/*` to Django so the browser sees a single origin.

## Consequences
Atomic changes across API and UI, one CI pipeline, simple onboarding. Revisit if teams or release
cadences diverge. Same-origin proxy avoids CORS and keeps cookie sessions simple.
