---
id: api-security
version: "1.0.0"
title: "API Security"
description: "Apply OWASP API Top 10 patterns to authentication, authorization, and input validation"
category: prevention
severity: high
applies_to:
  - "when generating HTTP handlers"
  - "when generating GraphQL resolvers"
  - "when generating gRPC service methods"
  - "when reviewing API endpoint changes"
languages: ["*"]
token_budget:
  minimal: 500
  compact: 750
  full: 2300
rules_path: "checklists/"
related_skills: ["secure-code-review", "secret-detection"]
last_updated: "2026-05-12"
sources:
  - "OWASP API Security Top 10 2023"
  - "OWASP Authentication Cheat Sheet"
  - "OAuth 2.0 Security Best Current Practice (RFC 9700)"
---

# API Security

## Rules (for AI agents)

### ALWAYS
- Require authentication on every non-public endpoint. Default to authenticated; opt
  out for genuinely public routes by explicit annotation.
- Apply authorization at the object level — confirm the authenticated subject actually
  has access to the requested resource ID, not just that they're logged in (defeats
  the OWASP API1 BOLA / IDOR class).
- Validate all request inputs against an explicit schema (JSON Schema, Pydantic,
  Zod, validator/v10 struct tags). Reject early; never propagate untrusted input
  deeper.
- Enforce rate limits at the route level for authentication endpoints, password reset,
  and any expensive operation.
- Use short-lived access tokens (≤ 1 hour) with refresh tokens, not long-lived bearer
  tokens.
- Return generic error messages externally (`invalid credentials`) and log specifics
  internally — avoid leaking which of username/password was wrong.
- Include `Cache-Control: no-store` on responses containing personal or sensitive
  data.

### NEVER
- Use sequential integer IDs in URLs for resources accessible across tenants. Use
  UUIDs or unguessable opaque IDs.
- Trust `Authorization` headers without verifying the signature and expiration.
- Accept `none` algorithm JWTs. Pin the expected algorithm at verification time.
- Mass-assign request bodies directly to ORM models (`User(**request.json)`) — this
  enables privilege escalation when the model has admin fields the user shouldn't
  control.
- Disable CSRF protection on state-changing endpoints used by browsers.
- Return stack traces or framework error pages to the client in production.
- Use `HTTP GET` for any state-changing operation — GET should be safe and
  idempotent.

### KNOWN FALSE POSITIVES
- Public marketing-site endpoints serving anonymous traffic legitimately have no auth
  and no rate limits beyond the load balancer.
- Sequential IDs in paths are fine for genuinely public, non-tenant-scoped resources
  (e.g. blog post slugs, public product catalog items).
- Health-check endpoints (`/healthz`, `/ready`) intentionally bypass auth.

## Context (for humans)

The OWASP API Top 10 differs from the web Top 10 mostly because APIs have weaker
defaults: they often skip CSRF, they expose object IDs directly, and they tend to
trust developer-provided client-side state. This skill codifies the most common
high-impact mistakes.

## References

- `checklists/auth_patterns.yaml`
- `checklists/input_validation.yaml`
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
