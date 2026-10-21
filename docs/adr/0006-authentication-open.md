# ADR-0006: Authentication approach (OPEN)

Status: proposed
Date: 2026-10-19

## Context
The scaffold uses Django session authentication with CSRF protection, which suits the same-origin
proxy. Sign-up, password reset, MFA and social login are not implemented.

## Options
1. django-allauth (self-hosted, MFA support, fewer moving parts).
2. External identity provider via OIDC (Auth0, Keycloak, Cognito): less code to secure, vendor cost.

## Decision needed before the pilot.
