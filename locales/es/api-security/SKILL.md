---
id: api-security
language: es
source_revision: "fbb3a823"
version: "1.0.0"
title: "Seguridad de API"
description: "Aplicar los patrones del OWASP API Top 10 para autenticación, autorización y validación de entrada"
category: prevention
severity: high
applies_to:
  - "al generar handlers HTTP"
  - "al generar resolvers de GraphQL"
  - "al generar métodos de servicio gRPC"
  - "al revisar cambios en endpoints de API"
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

# Seguridad de API

## Reglas (para agentes de IA)

### SIEMPRE
- Exigir autenticación en cada endpoint no público. Por defecto, autenticado; las
  rutas genuinamente públicas se marcan explícitamente.
- Aplicar autorización a nivel de objeto — confirmar que el sujeto autenticado
  realmente tiene acceso al ID del recurso solicitado, no solo que ha iniciado
  sesión (eso evita la clase OWASP API1 BOLA / IDOR).
- Validar todas las entradas de la petición contra un esquema explícito (JSON
  Schema, Pydantic, Zod, struct tags de validator/v10). Rechazar pronto; nunca
  propagar entrada no confiable hacia capas internas.
- Aplicar límites de tasa a nivel de ruta para endpoints de autenticación, reseteo
  de contraseña y cualquier operación costosa.
- Usar access tokens de vida corta (≤ 1 hora) con refresh tokens, no bearer
  tokens de larga duración.
- Devolver mensajes de error genéricos al exterior (`invalid credentials`) y
  registrar detalles internamente — evitar filtrar cuál de los dos (usuario o
  contraseña) estaba mal.
- Incluir `Cache-Control: no-store` en respuestas con datos personales o
  sensibles.

### NUNCA
- Usar IDs enteros secuenciales en URLs para recursos accesibles entre
  inquilinos. Usar UUIDs o IDs opacos no adivinables.
- Confiar en cabeceras `Authorization` sin verificar firma ni expiración.
- Aceptar JWTs con algoritmo `none`. Fijar el algoritmo esperado al verificar.
- Hacer mass-assignment del cuerpo de la petición directamente a modelos ORM
  (`User(**request.json)`) — esto habilita escalada de privilegios cuando el
  modelo tiene campos admin que el usuario no debería poder controlar.
- Deshabilitar la protección CSRF en endpoints que cambian estado y son usados
  por navegadores.
- Devolver stack traces o páginas de error del framework al cliente en
  producción.
- Usar `HTTP GET` para cualquier operación que cambie estado — GET debe ser
  seguro e idempotente.

### FALSOS POSITIVOS CONOCIDOS
- Los endpoints de sitios de marketing públicos que sirven tráfico anónimo
  legítimamente no tienen autenticación ni rate limit más allá del balanceador.
- Los IDs secuenciales en rutas son aceptables para recursos genuinamente
  públicos y no asociados a inquilinos (p. ej., slugs de blog, catálogo público
  de productos).
- Los endpoints de health check (`/healthz`, `/ready`) saltan la autenticación
  intencionadamente.

## Contexto (para humanos)

El OWASP API Top 10 difiere del Top 10 web sobre todo porque las APIs tienen
defaults más débiles: a menudo omiten CSRF, exponen IDs de objetos directamente
y tienden a confiar en estado del cliente proporcionado por el desarrollador.
Esta skill codifica los errores más comunes de alto impacto.

## Referencias

- `checklists/auth_patterns.yaml`
- `checklists/input_validation.yaml`
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
