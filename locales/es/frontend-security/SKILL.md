---
id: frontend-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de frontend"
description: "Endurecimiento en el navegador: XSS, CSP, CORS, SRI, DOM clobbering, sandboxing de iframe, Trusted Types"
category: prevention
severity: high
applies_to:
  - "al generar templates HTML / JSX / Vue / Svelte"
  - "al cablear headers de respuesta en una web app"
  - "al agregar etiquetas de script de terceros o recursos de CDN"
languages: ["html", "javascript", "typescript", "tsx", "jsx", "vue", "svelte"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2800
rules_path: "rules/"
related_skills: ["cors-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP XSS Prevention Cheat Sheet"
  - "OWASP Content Security Policy Cheat Sheet"
  - "CWE-79: Improper Neutralization of Input During Web Page Generation"
  - "MDN Trusted Types"
---

# Seguridad de frontend

## Reglas (para agentes de IA)

### SIEMPRE
- Tratar todos los datos de usuario/URL/storage como no confiables.
  Renderizar vía el escape del framework (`{}` en JSX/Vue/Svelte,
  `{{ }}` en templating). Para HTML crudo usar un sanitizer
  auditado (DOMPurify) con allowlist estricta.
- Enviar un header estricto `Content-Security-Policy`. Baseline
  mínima de producción: `default-src 'self'; script-src 'self'
  'nonce-<random>'; object-src 'none'; base-uri 'self';
  frame-ancestors 'none'; form-action 'self';
  upgrade-insecure-requests`. Usar nonces o hashes — nunca
  `'unsafe-inline'` en `script-src`.
- Setear `Strict-Transport-Security: max-age=63072000;
  includeSubDomains; preload`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer-when-downgrade` o más estricto, y
  `Permissions-Policy` para quitar features no usadas.
- Agregar `integrity="sha384-..." crossorigin="anonymous"` a cada
  `<script>` y `<link rel="stylesheet">` cargado desde un CDN.
- Agregar `sandbox="allow-scripts allow-same-origin"` (sólo los
  atributos necesarios) a cada `<iframe>`. Por defecto, sin flags
  de allow.
- Usar cookies con `Secure; HttpOnly; SameSite=Lax` (o `Strict`
  para flujos sensibles). Prefijo `__Host-` cuando no hay
  compartido entre subdominios.
- Habilitar Trusted Types donde lo permita el navegador
  (`Content-Security-Policy: require-trusted-types-for 'script'`)
  para que las asignaciones a sinks del DOM (`innerHTML`,
  `setAttribute('src', ...)` para scripts) deban pasar por una
  policy tipada.

### NUNCA
- Usar `dangerouslySetInnerHTML`, `v-html`, `{@html ...}`,
  `innerHTML =` o `document.write` con input no confiable.
- Usar `eval`, `new Function`, `setTimeout(string)`,
  `setInterval(string)` o `Function('return x')`.
- Inyectar input del usuario en `href`, `src`, `formaction`,
  `action` o cualquier atributo que porte URL sin validar el
  esquema (bloquear `javascript:`, `data:`, `vbscript:`).
- Usar `target="_blank"` sin `rel="noopener noreferrer"` — filtra
  `window.opener`.
- Confiar en nodos del DOM sólo por id. DOM clobbering: un
  `<input name="config">` controlado por el atacante sombrea
  `window.config`.
- Usar `postMessage` sin chequear `event.origin` contra una
  allowlist.
- Almacenar JWTs, refresh tokens o PII en `localStorage` /
  `sessionStorage` — cualquier XSS los exfiltra. Preferir cookies
  HttpOnly.
- Leer o escribir `document.cookie` desde JavaScript para cookies
  de auth — deberían ser HttpOnly de todos modos.

### FALSOS POSITIVOS CONOCIDOS
- Herramientas de admin internas que deliberadamente renderizan
  Markdown / texto rico desde autores confiables pueden usar
  `dangerouslySetInnerHTML` tras pasar por un sanitizer; documentar
  la llamada al sanitizer inline.
- Las extensiones de navegador a veces necesitan `'unsafe-eval'` en
  el CSP de la extensión; el CSP de la web app de cara al usuario
  igual debe prohibirlo.
- Conexiones WebSocket a endpoints no-same-origin están bien
  cuando el servidor hace validación de origin.

## Contexto (para humanos)

El OWASP XSS Prevention Cheat Sheet sigue siendo la referencia
autoritativa para las reglas de escape; CSP es la capa de defensa
en profundidad que convierte un escape olvidado en un reporte
logueado en lugar de una sesión robada. Trusted Types es el patrón
más nuevo y forzado por el navegador que mueve la pregunta "¿pasó
esto por un sanitizer?" del audit en runtime al sistema de tipos.

Los frontends generados por IA suelen ir a `innerHTML` y
`dangerouslySetInnerHTML` porque son más cortos; este skill es el
contrapeso.

## Referencias

- `rules/csp_defaults.json`
- `rules/xss_sinks.json`
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Cross-site scripting.
- [Trusted Types (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).
