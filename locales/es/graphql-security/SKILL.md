---
id: graphql-security
language: es
source_revision: "4c215e6f"
version: "1.0.0"
title: "Seguridad de GraphQL"
description: "Defender APIs GraphQL: límites de profundidad/complejidad, introspection en producción, abuso de batching/aliasing, autorización a nivel de campo, persisted queries"
category: prevention
severity: high
applies_to:
  - "al generar schemas, resolvers o configuración de servidor GraphQL"
  - "al cablear autenticación/autorización a un endpoint GraphQL"
  - "al agregar un gateway de API GraphQL público"
  - "al revisar la exposición del endpoint /graphql"
languages: ["javascript", "typescript", "python", "go", "java", "kotlin", "csharp", "ruby"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP GraphQL Cheat Sheet"
  - "CWE-400: Uncontrolled Resource Consumption"
  - "Apollo GraphQL Production Checklist"
  - "graphql-armor (Escape technologies)"
---

# Seguridad de GraphQL

## Reglas (para agentes de IA)

### SIEMPRE
- Imponer una **profundidad máxima** de query (típico: 7–10) y una
  **complejidad** (costo) de query en el servidor. Una query
  anidada de 5 niveles contra una relación many-to-many puede
  devolver miles de millones de nodos; sin un límite de costo, un
  solo cliente tira la base de datos.
- Deshabilitar **introspection** en producción. La introspection
  hace trivial el reconocimiento; los clientes legítimos tienen el
  schema integrado vía codegen o un artefacto `.graphql`.
- Usar **persisted queries** (hashes de operación en allowlist)
  para cualquier API pública / de alto tráfico. GraphQL anónimo
  arbitrario es el equivalente GraphQL de `eval(req.body)`.
- Aplicar **autorización a nivel de campo** en los resolvers, no
  sólo en el endpoint. GraphQL agrega muchos campos en una sola
  respuesta HTTP — un único `@auth` ausente en un campo sensible
  filtra datos en toda la query.
- Limitar el número de **aliases** por request (típico: 15) y el
  número de **operaciones por batch** (típico: 5). Apollo / Relay
  ambos permiten queries en batch — sin límites, esto es un
  primitivo de amplificación de N páginas de la API.
- Rechazar definiciones de **fragmentos circulares** temprano (la
  mayoría de servidores lo hacen, pero los executors custom no).
  Un fragmento auto-referente causa un costo exponencial en
  parse-time.
- Devolver errores genéricos a los clientes (`INTERNAL_SERVER_ERROR`,
  `UNAUTHORIZED`) y rutear stack traces / snippets SQL sólo a los
  logs del servidor. Los errores por defecto de Apollo filtran
  internals del schema y de la query.
- Setear un límite de tamaño de request (típico: 100 KiB) y un
  timeout de request (típico: 10 s) en la capa HTTP delante del
  servidor GraphQL. Una query GraphQL de 1 MiB no tiene uso
  legítimo.

### NUNCA
- Exponer introspection de `/graphql` en un endpoint de producción.
  El playground GraphQL (GraphiQL, Apollo Sandbox) también debe
  estar deshabilitado en builds de producción.
- Confiar en la profundidad / complejidad de una query porque
  "nuestros clientes sólo mandan queries bien formadas". Cualquier
  atacante puede armar a mano un request a `/graphql`.
- Permitir que directivas `@skip(if: ...)` / `@include(if: ...)`
  controlen los chequeos de autorización. Las directivas se
  ejecutan después de la autorización en la mayoría de los
  executors, pero el orden custom de directivas ha producido
  bypasses de authz.
- Implementar patrones N+1 en los resolvers (una query a la BD por
  cada registro padre). Usar un DataLoader o fetch por join. N+1
  es a la vez un bug de performance y un amplificador de DoS.
- Permitir uploads de archivos vía multipart GraphQL
  (`apollo-upload-server`, `graphql-upload`) sin límites de tamaño,
  validación de MIME, y virus scan fuera de banda. El CVE-2020-7754
  de 2020 (`graphql-upload`) mostró cómo un multipart mal formado
  puede tirar al servidor.
- Cachear respuestas GraphQL sólo por URL. POST `/graphql` siempre
  usa la misma URL; el caché debe indexar por hash de operación +
  variables + claims de auth para evitar fugas entre tenants.
- Exponer mutations que tomen objetos `input:` con JSON no
  confiable sin validación de schema. Los tipos GraphQL son
  obligatorios en la capa del schema, pero los tipos `JSON` /
  `Scalar` los esquivan por completo.

### FALSOS POSITIVOS CONOCIDOS
- Endpoints GraphQL internos de admin detrás de una VPN
  autenticada pueden legítimamente dejar introspection encendida
  por ergonomía de desarrollo.
- Las persisted queries con allowlist estático hacen redundantes
  los chequeos de profundidad / complejidad sobre esas operaciones
  — mantener los chequeos para cualquier operación que no esté en
  la allowlist (es decir, operaciones vía un flag `disabled`).
- APIs de datos públicas, de sólo lectura, pueden usar límites de
  costo muy altos con caching agresivamente configurado en la capa
  CDN; el trade-off se documenta por endpoint.

## Contexto (para humanos)

GraphQL le da a los clientes un lenguaje de queries. Ese lenguaje
es Turing-completo en la práctica — profundidad, aliasing,
fragmentos y unions se combinan para formar computación casi
arbitraria contra el grafo de resolvers. Tratar `/graphql` como un
único endpoint con controles simples de WAF / rate-limit es
inadecuado.

La era 2022-2024 de incidentes GraphQL (Hyatt, la investigación
de Slack desde Apollo, varios casos de account-takeover vía
batching) todos giraron en torno a o bien autorización ausente a
nivel de campo o bien análisis de costo ausente.
graphql-armor (Escape) y las reglas de validación incluidas en
Apollo ofrecen middleware listo para la mayoría de estas —
úsenlas.

## Referencias

- `rules/graphql_safe_config.json`
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- [Apollo Production Checklist](https://www.apollographql.com/docs/apollo-server/security/production-checklist/).
- [graphql-armor](https://escape.tech/graphql-armor/).
