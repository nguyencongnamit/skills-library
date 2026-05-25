---
id: secure-code-review
language: es
source_revision: "fbb3a823"
version: "1.0.0"
title: "Revisión de código segura"
description: "Aplicar patrones de OWASP Top 10 y CWE Top 25 durante la generación y revisión de código"
category: prevention
severity: high
applies_to:
  - "al generar código nuevo"
  - "al revisar pull requests"
  - "al refactorizar caminos sensibles a seguridad (auth, manejo de input, I/O de archivos)"
  - "al agregar nuevos handlers o endpoints HTTP"
languages: ["*"]
token_budget:
  minimal: 700
  compact: 900
  full: 2400
rules_path: "checklists/"
related_skills: ["api-security", "secret-detection", "infrastructure-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "SEI CERT Coding Standards"
---

# Revisión de código segura

## Reglas (para agentes de IA)

### SIEMPRE
- Usar queries parametrizadas / prepared statements para todo acceso a base
  de datos. Nunca construir SQL por concatenación de strings, incluso para
  inputs "confiables".
- Validar input en el trust boundary — tipo, longitud, caracteres permitidos,
  rango permitido — y rechazar antes de procesar.
- Codificar output para el contexto de renderizado (HTML escape para HTML,
  URL encode para query params, JSON encode para output JSON).
- Usar la librería de criptografía built-in del lenguaje, nunca crypto
  hecho a mano. Preferir AES-GCM para cifrado simétrico, Ed25519 / RSA-PSS
  para firmas, Argon2id / bcrypt para password hashing.
- Usar `crypto/rand` (Go), módulo `secrets` (Python), `crypto.randomBytes`
  (Node.js), o el CSPRNG de la plataforma para cualquier valor random que
  participe en seguridad (tokens, IDs, session keys).
- Setear headers de seguridad explícitos en responses HTTP:
  `Content-Security-Policy`, `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`.
- Usar el principio de mínimo privilegio para paths de archivo, usuarios
  de base de datos, políticas IAM y privilegios de proceso.

### NUNCA
- Construir queries SQL/NoSQL por concatenación de strings con input de
  usuario.
- Pasar input de usuario directamente a `exec`, `system`, `eval`,
  `Function()`, `child_process`, `subprocess.run(shell=True)`, o cualquier
  otro path de ejecución de comandos.
- Confiar en validación client-side. Siempre re-validar server-side.
- Usar `MD5` o `SHA1` para ningún propósito nuevo sensible a seguridad
  (passwords, firmas, HMAC). Usar SHA-256 / SHA-3 / BLAKE2 / Argon2id
  en su lugar.
- Usar modo ECB para ninguna cifrado, jamás. Preferir GCM, CCM, o
  ChaCha20-Poly1305.
- Usar `==` para comparación de password — usar una comparación de tiempo
  constante (`hmac.compare_digest`, `crypto.timingSafeEqual`,
  `subtle.ConstantTimeCompare`).
- Permitir que input de usuario determine paths de archivo sin
  canonicalización y checks de allowlist (defiende contra path traversal
  estilo `../../../etc/passwd`).
- Deshabilitar verificación de certificados TLS en código de producción —
  `verify=False`, `InsecureSkipVerify: true`, `rejectUnauthorized: false`.

### FALSOS POSITIVOS CONOCIDOS
- Herramientas internas de admin que ejecutan comandos shell intencionalmente
  contra argumentos confiables y fijos son aceptables cuando están
  documentadas y code-reviewed.
- Vectores de test criptográficos usando `MD5` / `SHA1` por compatibilidad
  con protocolos documentados (por ej. tests de interop legacy) son
  aceptables.
- Comparación de tiempo constante es overkill para comparaciones no
  secretas (igualdad de strings en logs, matching de tags).

## Contexto (para humanos)

La mayoría de las vulnerabilidades web modernas se reducen al mismo puñado
de causas raíz: fallar al validar input, fallar al usar la primitiva
criptográfica correcta, fallar al aplicar mínimo privilegio, fallar al
usar las defensas built-in del framework. Este skill es el checklist de
la IA para no caer en esas trampas.

## Referencias

- `checklists/owasp_top10.yaml`
- `checklists/injection_patterns.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
