# ADR-0003: Tenant isolation with PostgreSQL row-level security

Status: accepted
Date: 2026-10-19

## Context
A scanner stores sensitive findings about customers' weaknesses. An application-layer filter bug
must not become a cross-tenant breach.

## Decision
Every tenant-owned table has forced RLS keyed on `current_tenant()`, set per transaction. The app
connects as a non-superuser role. Queries also filter by tenant explicitly (two independent layers).
Child tables use composite foreign keys so a row cannot reference another tenant's parent.

## Consequences
Isolation is testable at the database level and fails closed. Costs: every table needs the helper
and a test; admin and support tooling must use a deliberate, audited path.
