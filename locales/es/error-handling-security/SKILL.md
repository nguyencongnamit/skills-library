---
id: error-handling-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad en el manejo de errores"
description: "Sin stack traces / SQL / paths / versiones de framework en respuestas al cliente; errores genéricos hacia afuera, errores estructurados en los logs"
category: prevention
severity: medium
applies_to:
  - "al generar handlers de error HTTP / GraphQL / RPC"
  - "al generar bloques exception / panic / rescue"
  - "al cablear páginas de error default del framework"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 900
  full: 1900
rules_path: "rules/"
related_skills: ["api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Error Handling Cheat Sheet"
  - "CWE-209 — Generation of Error Message Containing Sensitive Information"
  - "CWE-754 — Improper Check for Unusual or Exceptional Conditions"
---

# Seguridad en el manejo de errores

## Reglas (para agentes de IA)

### SIEMPRE
- Capturar excepciones en el boundary (handler HTTP, método RPC,
  consumer de mensajes). Loguearlas con contexto completo del lado
  servidor; devolver un error saneado hacia afuera.
- Las respuestas de error externas incluyen: un código de error
  estable, un mensaje corto legible por humanos y un ID de
  correlación / request. Nunca incluyen: stack trace, fragmento de
  SQL, path de archivo, hostname interno, banner de versión del
  framework.
- Loguear errores en el nivel adecuado: `ERROR` / `WARN` para fallas
  accionables; `INFO` para resultados de negocio esperados; `DEBUG`
  para detalle de diagnóstico (y sólo cuando se habilita
  explícitamente).
- Devolver respuestas de error uniformes en toda la superficie de la
  API — misma forma, mismo set de códigos — para que los atacantes no
  puedan inferir comportamiento a partir de variaciones de error
  (p. ej., login: mismo mensaje y mismo timing para "usuario
  incorrecto" vs "password incorrecto").
- Deshabilitar las páginas de error default del framework en
  producción (`app.debug = False` / `Rails.env.production?` /
  `Environment=Production` / `DEBUG=False`). Reemplazar con una
  página 5xx que devuelva sólo el ID de correlación.
- Usar un helper centralizado de render de errores para que las
  reglas de sanitización vivan en un solo lugar, no duplicadas.

### NUNCA
- Renderizar `traceback.format_exc()`, `e.toString()`,
  `printStackTrace()`, `panic` o páginas de debug del framework al
  cliente en producción.
- Eco de queries / parámetros SQL en mensajes de error —
  `IntegrityError: duplicate key value violates unique constraint
  "users_email_key"` le dice al atacante el nombre de la tabla y la
  columna.
- Filtrar información de presencia de registro: `User not found` vs
  `Invalid password` permite enumerar cuentas. Usar un único mensaje
  para ambos.
- Filtrar paths del filesystem (`/var/www/app/src/handlers.py`) o
  banners de versión (`X-Powered-By: Express/4.17.1`).
- Tratar `try / except: pass` como manejo de error; o la excepción es
  esperada (loguear + seguir) o no lo es (dejar que propague).
- Usar respuestas de error 4xx para validar la forma del input — los
  bots iteran sobre parámetros y usan el body de la respuesta para
  aprender el schema. Devolver un 400 uniforme más un ID de
  correlación para input mal formado.
- Mandar detalles completos de error (incluida PII) a servicios de
  error tracking de terceros sin un scrubber. Redactar `password`,
  `Authorization`, `Cookie`, `Set-Cookie`, `token`, `secret` y
  patrones comunes de PII.

### FALSOS POSITIVOS CONOCIDOS
- Páginas de error orientadas a developers en `localhost` / `*.local`
  están bien.
- Un puñado de endpoints de API (debug, admin, RPC interno) pueden
  legítimamente devolver más detalle; deben requerir callers
  autenticados y autorizados y nunca ser alcanzables desde internet.
- Health checks y smoke tests de CI exponen detalle intencionalmente
  cuando se invocan desde dentro del cluster.

## Contexto (para humanos)

CWE-209 es texto chico pero impacto grande: es cómo los atacantes
pasan de "este servicio existe" a "este servicio corre Spring 5.2
sobre Tomcat 9 con una tabla PostgreSQL llamada `users` y una columna
llamada `email_normalized`". Cada detalle extra en el mensaje de
error reduce el costo del siguiente ataque.

Esta skill es deliberadamente estrecha y se complementa con
`logging-security` (el lado *log* de la misma operación) y
`api-security` (la forma de la respuesta).

## Referencias

- `rules/error_response_template.json`
- `rules/redaction_patterns.json`
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
