---
id: logging-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de logging"
description: "Prevenir filtraciones de secretos/PII en logs, ataques de log-injection, ausencia de audit trails y retención débil"
category: prevention
severity: high
applies_to:
  - "al generar llamadas a logger o schemas de logging estructurado"
  - "al cablear log shippers, sinks, retención y controles de acceso"
  - "al revisar requisitos de audit logging"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["secret-detection", "error-handling-security", "compliance-awareness"]
last_updated: "2026-05-13"
sources:
  - "OWASP Logging Cheat Sheet"
  - "CWE-532 — Insertion of Sensitive Information into Log File"
  - "CWE-117 — Improper Output Neutralization for Logs"
  - "NIST SP 800-92 (Guide to Computer Security Log Management)"
---

# Seguridad de logging

## Reglas (para agentes de IA)

### SIEMPRE
- Loguear en un **formato estructurado** (JSON o logfmt) con nombres
  de campo estables. Incluir `timestamp`, `service`, `version`,
  `level`, `trace_id`, `span_id`, `user_id` (cuando hay autenticación),
  `request_id`, `event`.
- Pasar cada mensaje de log por un **redactor** antes de que llegue al
  sink: contraseñas, tokens, API keys, cookies, URLs completas que
  contengan `?token=`, patrones comunes de PII (estilo SSN, estilo
  tarjeta de crédito, opcionalmente email).
- Sanitizar newlines / caracteres de control en cualquier string
  controlado por el usuario antes de loguearlo (CWE-117): reemplazar
  `\n`, `\r`, `\t` para que un atacante no pueda inyectar líneas de
  log falsas.
- Loguear eventos relevantes para seguridad como **registros de
  auditoría inmutables**: éxito/fallo de login, retos de MFA, cambio
  de contraseña, cambio de rol, otorgar/revocar acceso, exportación
  de datos, acción de admin. Los registros de auditoría tienen
  retención más larga y acceso más estricto.
- Setear retención por categoría de dato, no global: corto para
  debug, largo para auditoría, nada de PII tras expirar el
  consentimiento.
- Enviar logs a un store centralizado y append-only (Cloud Logging,
  CloudWatch, Elastic, Loki) con acceso de lectura restringido a
  ingeniería / SecOps.
- Alertar ante logs faltantes de un servicio (falla silenciosa) y
  ante anomalías de volumen (pico 10x o caída 10x).

### NUNCA
- Loguear bodies completos de request / response en INFO. Los bodies
  contienen regularmente contraseñas, tokens, PII y archivos
  subidos.
- Loguear headers `Authorization`, headers `Cookie` / `Set-Cookie`,
  tokens en query-string, ni ningún campo nombrado `password`,
  `secret`, `token`, `key`, `private` o `credential` — ni siquiera
  tras "ofuscar" con `***`.
- Loguear sentencias SQL ya enlazadas completas con sus valores de
  parámetro; loguear en su lugar el template + *nombres* de
  parámetro + un identificador hasheado del valor.
- Permitir que usuarios sin privilegios lean logs crudos con datos
  de otros usuarios.
- Usar `print()` / `console.log` / `fmt.Println` simple en servicios
  de producción; usar el logger configurado para que redacción y
  estructura se apliquen de forma uniforme.
- Deshabilitar el logueo de intentos fallidos de autenticación para
  "reducir ruido" — la detección de fuerza bruta depende de esos
  registros.
- Loguear a un único archivo en disco local en producción; esos
  logs se pierden cuando el pod / container / VM muere.

### FALSOS POSITIVOS CONOCIDOS
- Los logs de health-check o probe del load balancer pueden
  legítimamente reducirse/suprimirse en el load balancer para
  ahorrar volumen.
- Un valor de `request_id` que parezca un token no es un token —
  los redactores que matchean patrones pueden sobre-redactar;
  whitelistear prefijos seguros conocidos (por ej. tus IDs de
  correlación `req_`).
- Los logs de acceso a APIs públicas anónimas sin headers de auth
  no son un problema de privacidad per se; las IPs de cliente
  pueden seguir siendo PII bajo GDPR.

## Contexto (para humanos)

Los logs son el lugar más común donde los secretos terminan en
texto plano — dumps de requests, trazas de excepciones, prints de
debug, telemetría de SDKs de terceros. El OWASP Logging Cheat Sheet
cubre las reglas operativas; NIST SP 800-92 cubre el lado de
retención / centralización / audit trail. Los requisitos de audit
trail aparecen bajo SOC 2 CC7.2, PCI-DSS 10, HIPAA §164.312(b) e
ISO 27001 A.12.4.

Este skill es el compañero de `secret-detection` (que escanea el
código) y `error-handling-security` (que sanitiza la respuesta
externa). Los logs están entre los dos y sangran en ambas
direcciones.

## Referencias

- `rules/redaction_patterns.json`
- `rules/audit_event_schema.json`
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final).
