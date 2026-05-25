---
id: protocol-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de protocolos"
description: "TLS 1.2+, mTLS, validación de certificados, HSTS, credenciales de canal gRPC, validación de Origin en WebSocket"
category: hardening
severity: critical
applies_to:
  - "al generar clientes y servidores HTTP / gRPC / WebSocket / SMTP / de base de datos"
  - "al generar configuración de TLS en código o en config de plataforma"
  - "al generar auth servicio-a-servicio"
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

# Seguridad de protocolos

## Reglas (para agentes de IA)

### SIEMPRE
- Default a **TLS 1.3** para clientes y servidores nuevos; permitir TLS
  1.2 sólo por interoperabilidad con peers legacy. Deshabilitar TLS
  1.0/1.1, SSLv2/v3.
- Validar el certificado del servidor: cadena hacia una CA confiable,
  el nombre coincide con el hostname esperado (o SAN), no expirado, no
  revocado (OCSP stapling habilitado).
- Habilitar HSTS en las respuestas HTTP para todo lo servido sobre
  HTTPS: `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.
  Agregar el host al HSTS preload list una vez estable.
- Usar **mutual TLS** (mTLS) para tráfico servicio-a-servicio dentro
  de un trust domain (mesh: Istio / Linkerd; standalone: SPIFFE /
  SPIRE para identidad).
- Para clientes/servidores gRPC, usar `grpc.secure_channel` /
  `grpc.SslCredentials` / `credentials.NewTLS` — nunca
  `insecure_channel` en producción.
- Para servidores WebSocket, validar el header `Origin` contra un
  allowlist y autenticar el handshake (cookies + token CSRF, o un
  bearer en query-string usado sólo en el upgrade y re-validado).
- Para tokens servicio-a-servicio, preferir **SPIFFE IDs**
  (`spiffe://trust-domain/...`) con certs de workload de vida corta,
  por encima de API keys de vida larga.
- Pinear el certificado (pinning de public key) para clientes
  móviles / desktop de alto riesgo que llaman al backend del operador.

### NUNCA
- Deshabilitar la verificación de certificado (`InsecureSkipVerify: true`,
  `verify=False`, `rejectUnauthorized: false`,
  `CURLOPT_SSL_VERIFYPEER=0`). El único uso aceptable es en un test
  unitario que corre contra un cert efímero de localhost.
- Implementar un `X509TrustManager` / `HostnameVerifier` /
  `URLSessionDelegate` / `ServerCertificateValidationCallback` custom
  que retorne incondicionalmente "trusted".
- Mezclar recursos HTTP y HTTPS en la misma página (mixed content) —
  los navegadores modernos bloquearán subrecursos, pero las APIs
  siguen vulnerables a downgrade MITM.
- Enviar tokens / passwords sobre HTTP plano — incluso en localhost en
  dev, salvo que el entorno de dev esté documentado como no relevante
  para seguridad.
- Usar `grpc.insecure_channel(...)` en código de producción.
- Confiar en el header `Host` / `X-Forwarded-Host` / `Forwarded` sin
  un allowlist; las URLs absolutas construidas a partir de `Host`
  habilitan host-header injection y password-reset poisoning.
- Reenviar headers `Authorization` / `Cookie` entrantes a ciegas a
  través de orígenes dentro de tu service mesh — re-derivar la
  identidad desde mTLS o un service token.
- Habilitar TLS renegotiation en clientes que controlas; pinear a
  `tls.NoRenegotiation` donde esté disponible.

### FALSOS POSITIVOS CONOCIDOS
- Servidores de dev solo-localhost con certs self-signed y
  documentación explícita están bien; los tests de CI contra certs
  efímeros firmados por CA están bien.
- Un número pequeño de integraciones legacy enterprise requieren TLS
  1.2 con un cipher específico; documentar la excepción y aislar la
  integración detrás de un proxy.
- Los endpoints públicos read-only (por ej., status pages) pueden
  legítimamente servirse por HTTP por cacheabilidad, aunque HTTPS
  sigue siendo preferido.

## Contexto (para humanos)

NIST SP 800-52 Rev. 2 es la referencia TLS autoritativa del gobierno
de EE. UU.; el RFC 8446 es TLS 1.3 en sí. El modo de fallo recurrente
en code review es **`InsecureSkipVerify`** (o sus equivalentes en cada
lenguaje) — usualmente introducido "para hacer andar los tests" y
nunca revertido.

Este skill emparejado naturalmente con `crypto-misuse` (elección de
algoritmo) y `auth-security` (emisión de tokens).

## Referencias

- `rules/tls_defaults.json`
- `rules/cert_validation_sinks.json`
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-52/rev-2/final).
- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446).
- [OWASP Transport Layer Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).
- [CWE-295](https://cwe.mitre.org/data/definitions/295.html) — Improper Certificate Validation.
