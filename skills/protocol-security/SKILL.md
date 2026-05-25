---
id: protocol-security
version: "1.0.0"
title: "Protocol Security"
description: "TLS 1.2+, mTLS, certificate validation, HSTS, gRPC channel credentials, WebSocket origin checks"
category: hardening
severity: critical
applies_to:
  - "when generating HTTP / gRPC / WebSocket / SMTP / database clients & servers"
  - "when generating TLS configuration in code or platform config"
  - "when generating service-to-service auth"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["crypto-misuse", "frontend-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-52 Rev. 2 (TLS Guidelines)"
  - "RFC 8446 — TLS 1.3"
  - "RFC 6797 — HSTS"
  - "OWASP Transport Layer Security Cheat Sheet"
  - "CWE-295, CWE-326, CWE-319, CWE-757"
---

# Protocol Security

## Rules (for AI agents)

### ALWAYS
- Default to **TLS 1.3** for new clients and servers; permit TLS 1.2 only for
  interop with legacy peers. Disable TLS 1.0/1.1, SSLv2/v3.
- Validate the server certificate: chain to a trusted CA, name matches the
  expected hostname (or SAN), not expired, not revoked (OCSP stapling
  enabled).
- Enable HSTS on HTTP responses for everything served over HTTPS:
  `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
  Add the host to the HSTS preload list once stable.
- Use **mutual TLS** (mTLS) for service-to-service traffic inside a trust
  domain (mesh: Istio / Linkerd; standalone: SPIFFE / SPIRE for identity).
- For gRPC clients/servers, use `grpc.secure_channel` /
  `grpc.SslCredentials` / `credentials.NewTLS` — never `insecure_channel`
  in production.
- For WebSocket servers, validate the `Origin` header against an allowlist
  and authenticate the handshake (cookies + CSRF token, or a query-string
  bearer used once at upgrade and re-validated).
- For service-to-service tokens, prefer **SPIFFE IDs** (`spiffe://trust-domain/...`)
  with short-lived workload certs over long-lived API keys.
- Pin the certificate (public key pinning) for high-risk mobile / desktop
  clients calling back to the operator's own backend.

### NEVER
- Disable certificate verification (`InsecureSkipVerify: true`,
  `verify=False`, `rejectUnauthorized: false`,
  `CURLOPT_SSL_VERIFYPEER=0`). The only acceptable use is in a unit test
  that runs against a localhost ephemeral cert.
- Implement a custom `X509TrustManager` / `HostnameVerifier` /
  `URLSessionDelegate` / `ServerCertificateValidationCallback` that
  unconditionally returns trusted.
- Mix HTTP and HTTPS resources on the same page (mixed content) — modern
  browsers will block subresources, but APIs are still vulnerable to MITM
  downgrade.
- Send tokens / passwords over plain HTTP — even on localhost in dev unless
  the dev environment is documented as not security-relevant.
- Use `grpc.insecure_channel(...)` in production code.
- Trust the `Host` / `X-Forwarded-Host` / `Forwarded` header without an
  allowlist; absolute URLs built from `Host` enable host-header injection
  and password-reset poisoning.
- Forward incoming `Authorization` / `Cookie` headers blindly across origins
  in your service mesh — re-derive identity from mTLS or a service token.
- Enable TLS renegotiation on clients you control; pin to `tls.NoRenegotiation`
  where available.

### KNOWN FALSE POSITIVES
- Localhost-only dev servers with self-signed certs and explicit
  documentation are fine; CI tests against ephemeral CA-signed certs are
  fine.
- A small number of legacy enterprise integrations require TLS 1.2 with a
  specific cipher; document the exception and isolate the integration
  behind a proxy.
- Public read-only endpoints (e.g., status pages) can legitimately serve
  over HTTP for cacheability, though HTTPS is still preferred.

## Context (for humans)

NIST SP 800-52 Rev. 2 is the authoritative US-government TLS reference;
RFC 8446 is TLS 1.3 itself. The recurring failure mode in code review is
**`InsecureSkipVerify`** (or its equivalents in every language) — usually
introduced "to make tests work" and never reverted.

This skill pairs naturally with `crypto-misuse` (algorithm choice) and
`auth-security` (token issuance).

## References

- `rules/tls_defaults.json`
- `rules/cert_validation_sinks.json`
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final).
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation.
