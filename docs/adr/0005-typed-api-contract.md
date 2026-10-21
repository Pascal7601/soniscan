# ADR-0005: OpenAPI as the single API contract

Status: accepted
Date: 2026-10-19

## Decision
DRF + drf-spectacular generate `backend/openapi.yaml`; `openapi-typescript` and `openapi-fetch`
generate the frontend client types. Both generated files are committed and CI fails on drift.

## Consequences
API changes surface as compile errors in the frontend. Serializers must be declared explicitly.
