---
id: auth-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de autenticación y autorización"
description: "JWT, OAuth 2.0 / OIDC, gestión de sesiones, CSRF, hashing de contraseñas y aplicación de MFA"
category: prevention
severity: critical
applies_to:
  - "al generar flujos de login / registro / reseteo de contraseña"
  - "al generar emisión o verificación de JWT"
  - "al generar código de cliente o servidor OAuth 2.0 / OIDC"
  - "al configurar cookies de sesión, tokens CSRF, MFA"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1300
  full: 2700
rules_path: "rules/"
related_skills: ["api-security", "crypto-misuse", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Authentication Cheat Sheet"
  - "OWASP Session Management Cheat Sheet"
  - "RFC 6749 — OAuth 2.0"
  - "RFC 7519 — JSON Web Token"
  - "RFC 9700 — OAuth 2.0 Security BCP"
  - "NIST SP 800-63B (Authenticator Assurance)"
---

# Seguridad de autenticación y autorización

## Reglas (para agentes de IA)

### SIEMPRE
- Para verificación de JWT, fijar el algoritmo esperado (`RS256`, `EdDSA` o
  `ES256`) y verificar `iss`, `aud`, `exp`, `nbf` e `iat`. Rechazar `alg=none`
  y cualquier algoritmo inesperado.
- Para clientes públicos OAuth 2.0 (SPA / móvil / CLI), usar el **flujo de
  authorization code con PKCE** (S256). Nunca el implicit flow. Nunca el
  resource owner password credentials grant.
- Cookies de sesión: `Secure; HttpOnly; SameSite=Lax` (o `Strict` para flujos
  sensibles). Usar el prefijo `__Host-` cuando no haya compartición de
  subdominios.
- Rotar el identificador de sesión en login y en cambio de privilegios. Atar
  la sesión al user agent solo como señal blanda — nunca como única
  verificación.
- Hashear contraseñas con argon2id (m=64 MiB, t=3, p=1) y un salt aleatorio
  por usuario. Bcrypt cost ≥ 12 o scrypt N≥2^17 son alternativas aceptables
  para sistemas legacy. PBKDF2-SHA256 requiere ≥ 600.000 iteraciones (mínimo
  OWASP 2023).
- Exigir longitud de contraseña ≥ 12 caracteres sin reglas de composición;
  permitir Unicode; comprobar contra una lista de contraseñas filtradas
  (HIBP / API k-anonymity de pwned-passwords).
- Implementar lockout de cuenta *o* rate limiting para intentos de contraseña
  (NIST SP 800-63B §5.2.2: máximo 100 fallos en 30 días).
- Implementar protección CSRF para peticiones que cambian estado y son
  alcanzables desde una sesión de navegador: synchronizer token, double-submit
  cookie, o `SameSite=Strict` para endpoints de alto riesgo.
- Requerir MFA / step-up para operaciones administrativas, cambios de
  contraseña, cambios de dispositivo MFA, cambios de facturación.
- Para OIDC, validar el `nonce` que enviaste contra el `nonce` del ID token;
  validar `at_hash` / `c_hash` cuando estén presentes.

### NUNCA
- Usar `Math.random()` (ni ningún RNG que no sea CSPRNG) para generar IDs de
  sesión, tokens de reseteo, códigos de recuperación MFA o claves de API.
- Aceptar JWT `alg=none`; o aceptar HS256 desde un cliente cuando el emisor
  firma con RS256 (ataque clásico de confusión de algoritmo).
- Comparar contraseñas o hashes de tokens con `==` / `strcmp`; usar un
  comparador de tiempo constante.
- Almacenar contraseñas de forma reversible (cifradas en vez de hasheadas).
  El almacenamiento debe ser unidireccional.
- Filtrar cuál de usuario/contraseña era incorrecto. Devolver un mensaje
  genérico "invalid credentials".
- Poner access tokens, refresh tokens o IDs de sesión en query strings de URL
  — se filtran a logs, cabeceras Referer e historial del navegador.
- Usar `localStorage` / `sessionStorage` para guardar refresh tokens de larga
  vida. Usar cookies HttpOnly.
- Confiar en roles / claims provistos por el cliente en la capa API —
  rederivar el sujeto autenticado y consultar autorización server-side en
  cada petición.
- Emitir access tokens de larga vida (>1 hora); apoyarse en refresh tokens
  con rotación.
- Usar el implicit flow o el password grant.

### FALSOS POSITIVOS CONOCIDOS
- Tokens servicio-a-servicio con TTLs largos son a veces aceptables cuando se
  guardan en un secret manager y están atados a una identidad de workload
  específica.
- Auth "magic link" en desarrollo local sin hashing de contraseña para
  usuarios efímeros de dev está bien si está protegido por una env flag y
  desactivado en producción.
- Tokens en query de URL son tolerables en *un* sitio — el retorno del
  authorization code de OAuth — porque el valor es de vida corta y de un
  solo uso.

## Contexto (para humanos)

Los fallos de autenticación aparecen consistentemente en OWASP Top 10
(A07:2021 — Identification and Authentication Failures). Los modos comunes
son: almacenamiento débil de contraseñas, tokens predecibles, ausencia de
MFA, mala configuración de JWT y fijación de sesión. RFC 9700 (OAuth 2.0
Security BCP) y NIST SP 800-63B son las referencias autoritativas para la
receta.

Los asistentes de IA tienden a generar auth "funciona en dev": JWTs HS256
con secretos hardcoded, `bcrypt.hash` con cost 10 por defecto, sin PKCE,
tokens en localStorage. Esta skill atrapa cada uno de esos.

## Referencias

- `rules/jwt_safe_config.json`
- `rules/oauth_flows.json`
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
