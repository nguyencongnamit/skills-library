---
id: cors-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad CORS"
description: "Configuración CORS estricta: nada de wildcard con credenciales, allowlist de orígenes, caché de preflight razonable, cabeceras expuestas mínimas"
category: prevention
severity: high
applies_to:
  - "al generar middleware CORS o configuración del framework"
  - "al cablear cabeceras CORS de API Gateway / CloudFront / Nginx"
  - "al revisar un endpoint cross-origin expuesto al navegador"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1000
  full: 2000
rules_path: "rules/"
related_skills: ["frontend-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP HTML5 Security Cheat Sheet — CORS"
  - "CWE-942 — Permissive Cross-domain Policy with Untrusted Domains"
  - "Fetch Living Standard (CORS)"
---

# Seguridad CORS

## Reglas (para agentes de IA)

### SIEMPRE
- Usar una **allowlist** de orígenes, no `*`. Reflejar la cabecera `Origin`
  entrante solo cuando coincide con una entrada conocida en la
  configuración (o con un regex precompilado de nombres de host
  controlados por el operador).
- Si las respuestas incluyen credenciales (cookies, `Authorization`),
  establecer `Access-Control-Allow-Credentials: true` **y** asegurar que
  `Access-Control-Allow-Origin` sea una única cadena de origen específica
  — nunca `*`.
- Incluir `Vary: Origin` en respuestas cuyo cuerpo dependa del `Origin`
  de la petición, para que los cachés no sirvan la respuesta de un
  origen a otro.
- Restringir `Access-Control-Allow-Methods` del preflight a los métodos
  reales que el endpoint acepta; restringir `Access-Control-Allow-Headers`
  a las cabeceras realmente consumidas.
- Configurar `Access-Control-Max-Age` a un valor razonable (≤ 86400 en
  producción) para amortizar la latencia del preflight sin clavar una
  allowlist mala.
- Mantener la allowlist en código (o en un archivo de configuración
  versionado), no derivada de una base de datos — para que los atacantes
  no puedan añadir su origen insertando una fila.

### NUNCA
- Establecer `Access-Control-Allow-Origin: *` junto con
  `Access-Control-Allow-Credentials: true`. La spec Fetch lo prohíbe por
  una razón — los navegadores rechazarán la respuesta, pero el problema
  mayor es que un proxy / caché upstream ya puede haberla filtrado.
- Reflejar la cabecera `Origin` sin chequeo de allowlist
  (`Access-Control-Allow-Origin: <Origin>` para todo origen entrante).
  Eso es lo mismo que `*` para credenciales pero con peor cacheo.
- Permitir `null` como Origin. `null` es lo que Chrome envía desde
  iframes sandboxed, URIs `data:` y `file://` — ninguno debería tener
  acceso credenciado a tu API.
- Permitir subdominios arbitrarios con un regex como `.*\.example\.com$`
  sin considerar el secuestro de subdominio. Fijar subdominios
  específicos; tratar `*.example.com` como una decisión deliberada
  acoplada a controles de propiedad de subdominios.
- Exponer cabeceras internas vía `Access-Control-Expose-Headers`.
  Limitar al conjunto mínimo que el frontend realmente necesita.
- Usar CORS como autorización. CORS es una política de *navegador*; no
  detiene server-to-server, curl ni clientes no-navegador. Autentica la
  petición correctamente.

### FALSOS POSITIVOS CONOCIDOS
- APIs verdaderamente públicas y no autenticadas (p. ej. datos abiertos,
  endpoints CDN de marketing) pueden usar legítimamente
  `Access-Control-Allow-Origin: *` *sin* credenciales.
- Herramientas internas de admin restringidas a una red privada pueden
  usar un único origen fijo; la preocupación del wildcard no aplica
  porque no hay llamadores cross-origin.
- Algunas integraciones (Stripe.js, Plaid, Auth0) esperan cabeceras CORS
  específicas — lee la sección CORS de cada proveedor antes de relajar
  la línea base.

## Contexto (para humanos)

CORS se entiende mal ampliamente como un control de seguridad. No lo es
— es una *relajación* de la política del mismo origen. El control de
seguridad es la autenticación. La mala configuración de CORS importa
porque, combinada con cookies o cabeceras `Authorization`, da a orígenes
no confiables la capacidad de hacer peticiones cross-origin credenciadas
y leer la respuesta.

Esta skill es corta por diseño — la matriz de combinaciones malas es
finita y las reglas son contundentes.

## Referencias

- `rules/cors_safe_config.json`
- [OWASP CORS Origin Header Scrutiny](https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny).
- [CWE-942](https://cwe.mitre.org/data/definitions/942.html).
- [Fetch — CORS protocol](https://fetch.spec.whatwg.org/#http-cors-protocol).
