---
id: ssrf-prevention
language: es
source_revision: "4c215e6f"
version: "1.0.0"
title: "Prevención de SSRF"
description: "Defensa contra Server-Side Request Forgery: bloqueo de metadata cloud, filtrado de IPs internas, defensa contra DNS rebinding, fetching de URL basado en allowlist"
category: prevention
severity: critical
applies_to:
  - "al generar código que hace fetch de una URL provista por el cliente"
  - "al cablear webhooks, image proxies, PDF renderers, oEmbed fetchers"
  - "al correr en cualquier entorno cloud con un servicio de instance metadata"
  - "al revisar un wrapper de URL-parsing o HTTP-client"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "cors-security", "infrastructure-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SSRF Prevention Cheat Sheet"
  - "CWE-918: Server-Side Request Forgery"
  - "Capital One 2019 breach post-mortem (IMDSv1 SSRF)"
  - "AWS IMDSv2 documentation"
  - "PortSwigger Web Security Academy — SSRF labs"
---

# Prevención de SSRF

## Reglas (para agentes de IA)

### SIEMPRE
- Validar **cada** URL traída en nombre de un cliente a través de una
  **allowlist** de hosts esperados. La allowlist es la única defensa
  durable — las block-lists son evitables vía encoding tricks, IPv6
  dual-stack y DNS rebinding.
- Resolver el hostname **una vez**, validar la IP resuelta contra tu
  block-list de rangos privados / reservados / link-local, luego
  conectar a esa IP pineada usando SNI. Si no, un atacante puede
  hacer un race de DNS rebind entre validación y connect
  (`time-of-check / time-of-use`).
- Bloquear en la capa de red **y** en la capa de aplicación. Cortar
  el egress a `169.254.169.254`, `[fd00:ec2::254]`,
  `metadata.google.internal` y `100.100.100.200` desde cualquier
  servicio que no necesite legítimamente el servicio de metadata.
- Enforzar **IMDSv2** en AWS EC2 (session-token, hop-limit=1). IMDSv1
  — el patrón que explotó el breach de Capital One de 2019 — debe
  deshabilitarse a nivel de instancia.
- Deshabilitar redirects HTTP por default en fetchers server-side
  (o seguir solo un número pequeño y acotado, re-validando la nueva
  URL contra la allowlist en cada hop). El bypass más común de SSRF
  es `https://allowed.example.com` retornando un 302 a
  `http://169.254.169.254/...`.
- Usar un HTTP client separado y restringido para URLs *controladas
  por el usuario* vs URLs *internas*. Usar el client equivocado
  debe fallar cerrado (por ej. vía distinción de tipo en Go / Rust /
  TypeScript).
- Parsear URLs con un único parser bien conocido (`net/url.Parse` de
  Go, `urllib.parse` de Python, `new URL()` de JavaScript). Los
  parsers diferenciales entre por ej. WHATWG y RFC-3986 son una
  clase documentada de bypass de SSRF.

### NUNCA
- Confiar en un hostname / IP provisto por el usuario. Siempre
  re-resolver en tu resolver de confianza y re-chequear la
  dirección resuelta.
- Conectar a una URL basándose en su hostname cuando el protocolo
  permite redirects — `gopher://`, `dict://`, `file://`, `jar://`,
  `netdoc://`, `ldap://` son todos amplificadores comunes de SSRF.
  Restringir a `http://` y `https://` (y `ftp://` solo si realmente
  lo necesitás).
- Confiar en `0.0.0.0`, `127.0.0.1`, `[::]`, `[::1]`, `localhost`, o
  `*.localhost.test` — todos llegan a la instancia local. La lista
  también debe incluir link-local `169.254.0.0/16`, IPv4-mapped
  IPv6 `::ffff:127.0.0.1`, y IPv6 ULA `fc00::/7`.
- Usar el string de URL del usuario en una línea de log o un
  response de error — puede ser el oráculo de reflexión de SSRF
  que convierte SSRF ciego en SSRF de exfiltración de data.
- Correr un sidecar / proxy de bloqueo de metadata como **única**
  defensa — un atacante que encuentra un pseudo-URL de
  Unix-domain-socket o un hostname mal configurado puede rutear
  alrededor del proxy. La allowlist a nivel aplicación sigue siendo
  requerida.
- Permitir IDN / Punycode en URLs de usuario sin normalización —
  los ataques de homógrafos IDN evitan checks naive de string-
  allowlist (`gооgle.com` con o cirílica ≠ `google.com`).

### FALSOS POSITIVOS CONOCIDOS
- Integraciones server-to-server donde ambos lados son
  controlados por el operador y la URL está hardcoded en config
  (no provista por el usuario) — la allowlist acá es el propio
  config estático.
- Llamadas service-to-service local-de-cluster en Kubernetes —
  estas no pasan por input de usuario, pero ojo con cualquier
  network policy cross-namespace.
- Webhooks salientes **al** cliente (por ej. Slack, Discord,
  Microsoft Teams webhooks). Validar que el host de la URL esté
  en la allowlist documentada de la integración, no arbitrario.

## Contexto (para humanos)

SSRF es ahora el vector de acceso inicial de facto para breaches
cloud. La cadena es: una URL provista por el usuario → el server
hace fetch → el server tiene credenciales implícitas (IAM de
metadata cloud, APIs internas de admin, endpoints RPC) → el
atacante roba las credenciales. El breach de Capital One en 2019
(80M registros de clientes) fue un caso de libro de SSRF +
exfiltración por IMDSv1. Los fixes son simples y bien documentados;
los patrones reaparecen porque URL-fetching es una esquina chica
de la mayoría de los codebases.

Este skill enfatiza las clases de DNS-rebinding y redirect-bypass
porque ahí es donde los validators de URL generados por IA fallan
más seguido — el bloqueo obvio de 169.254.169.254 es fácil de
agregar, pero el patrón allow-only-after-resolve-and-pin requiere
más pensamiento.

## Referencias

- `rules/ssrf_sinks.json`
- `rules/cloud_metadata_endpoints.json`
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
- [Capital One 2019 breach DOJ filing](https://www.justice.gov/usao-wdwa/press-release/file/1188626/download).
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf).
