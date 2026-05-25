---
id: protocol-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Protokoll-Sicherheit"
description: "TLS 1.2+, mTLS, Zertifikatsvalidierung, HSTS, gRPC-Channel-Credentials, WebSocket-Origin-Checks"
category: hardening
severity: critical
applies_to:
  - "beim Erzeugen von HTTP-/gRPC-/WebSocket-/SMTP-/Datenbank-Clients und -Servern"
  - "beim Erzeugen von TLS-Konfiguration in Code oder Plattform-Config"
  - "beim Erzeugen von Service-zu-Service-Auth"
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

# Protokoll-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Standardmäßig **TLS 1.3** für neue Clients und Server; TLS 1.2 nur
  zur Interoperabilität mit Legacy-Peers erlauben. TLS 1.0/1.1,
  SSLv2/v3 deaktivieren.
- Server-Zertifikat validieren: Kette zu einer vertrauenswürdigen CA,
  Name passt zum erwarteten Hostname (oder SAN), nicht abgelaufen,
  nicht widerrufen (OCSP-Stapling aktiviert).
- HSTS in HTTP-Responses für alles, was über HTTPS ausgeliefert wird,
  aktivieren: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
  Den Host nach Stabilisierung in die HSTS-Preload-Liste eintragen.
- **Mutual TLS** (mTLS) für Service-zu-Service-Traffic innerhalb einer
  Trust-Domain einsetzen (Mesh: Istio / Linkerd; standalone:
  SPIFFE / SPIRE für Identity).
- Für gRPC-Clients/-Server `grpc.secure_channel` /
  `grpc.SslCredentials` / `credentials.NewTLS` verwenden — nie
  `insecure_channel` in Produktion.
- Für WebSocket-Server den `Origin`-Header gegen eine Allowlist
  validieren und den Handshake authentifizieren (Cookies + CSRF-Token,
  oder ein Query-String-Bearer, der nur beim Upgrade benutzt und neu
  validiert wird).
- Für Service-zu-Service-Tokens **SPIFFE-IDs**
  (`spiffe://trust-domain/...`) mit kurzlebigen Workload-Certs
  gegenüber langlebigen API-Keys bevorzugen.
- Zertifikat (Public-Key-Pinning) für High-Risk-Mobile-/Desktop-
  Clients pinnen, die zum eigenen Backend zurückrufen.

### NIE
- Zertifikatsverifikation deaktivieren (`InsecureSkipVerify: true`,
  `verify=False`, `rejectUnauthorized: false`,
  `CURLOPT_SSL_VERIFYPEER=0`). Akzeptabel nur in einem Unit-Test
  gegen ein ephemerales Localhost-Cert.
- Einen Custom-`X509TrustManager` / `HostnameVerifier` /
  `URLSessionDelegate` / `ServerCertificateValidationCallback`
  implementieren, der bedingungslos "trusted" zurückgibt.
- HTTP- und HTTPS-Ressourcen auf derselben Seite mischen (Mixed
  Content) — moderne Browser blocken Subresourcen, APIs bleiben
  aber für MITM-Downgrade verwundbar.
- Tokens / Passwörter über reines HTTP schicken — auch nicht auf
  Localhost im Dev, es sei denn die Dev-Umgebung ist explizit als
  nicht sicherheitsrelevant dokumentiert.
- `grpc.insecure_channel(...)` in Produktionscode verwenden.
- Dem `Host`- / `X-Forwarded-Host`- / `Forwarded`-Header ohne
  Allowlist trauen; aus `Host` gebaute absolute URLs ermöglichen
  Host-Header-Injection und Password-Reset-Poisoning.
- Eingehende `Authorization`- / `Cookie`-Header blind über Origins
  hinweg im Service Mesh weiterreichen — Identität aus mTLS oder
  einem Service-Token neu ableiten.
- TLS-Renegotiation auf Clients aktivieren, die du kontrollierst;
  wo verfügbar auf `tls.NoRenegotiation` pinnen.

### BEKANNTE FALSCH-POSITIVE
- Nur-Localhost-Dev-Server mit Self-Signed-Certs und expliziter
  Dokumentation sind okay; CI-Tests gegen ephemerale CA-signed
  Certs sind okay.
- Eine kleine Anzahl Legacy-Enterprise-Integrationen erfordert TLS
  1.2 mit einer bestimmten Cipher; die Ausnahme dokumentieren und
  die Integration hinter einem Proxy isolieren.
- Öffentliche Read-Only-Endpunkte (z. B. Status-Pages) können
  legitim über HTTP ausgeliefert werden (Cacheability), HTTPS bleibt
  aber bevorzugt.

## Kontext (für Menschen)

NIST SP 800-52 Rev. 2 ist die autoritative TLS-Referenz der US-
Regierung; RFC 8446 ist TLS 1.3 selbst. Der wiederkehrende
Fehlermodus im Code-Review ist **`InsecureSkipVerify`** (oder seine
Äquivalente in jeder Sprache) — meist eingeführt, "um die Tests zum
Laufen zu bringen", und nie zurückgenommen.

Dieser Skill passt natürlich zu `crypto-misuse` (Algorithmuswahl) und
`auth-security` (Token-Ausstellung).

## Referenzen

- `rules/tls_defaults.json`
- `rules/cert_validation_sinks.json`
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final).
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation.
