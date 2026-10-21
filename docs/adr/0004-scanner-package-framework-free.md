# ADR-0004: Scanner engine is framework-free

Status: accepted
Date: 2026-10-19

## Decision
`backend/scanner/` contains checks, types and the SSRF guard with no Django, DRF or Celery
imports (enforced by import-linter). Network access is injected through small protocols.

## Consequences
Checks are unit-testable without a database, the engine can move to separate workers or another
runtime later, and the riskiest code stays small and reviewable.
