# ADR-0002: Django migrations are the source of truth for the schema

Status: accepted
Date: 2026-10-19

## Context
The design relies on database features Django does not model: row-level security, composite
tenant foreign keys, triggers.

## Decision
Models and auto-generated migrations define tables and constraints. Features Django cannot express
are hand-written `RunSQL` migrations built from helpers in `apps/core/db.py`. `docs/db/reference-schema.sql`
is a reviewed reference, not executed.

## Consequences
One migration history, reversible changes, no drift (CI runs `makemigrations --check`).
Hand-written migrations require security review (see CODEOWNERS).
