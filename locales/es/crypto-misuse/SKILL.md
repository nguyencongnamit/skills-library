---
id: crypto-misuse
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Mal uso criptográfico"
description: "Bloquear cifrados débiles, RNG predecibles, claves de tamaño insuficiente, mal uso de slow-hash y comparaciones no constantes en tiempo"
category: prevention
severity: critical
applies_to:
  - "al generar código que hashea / cifra / firma"
  - "al generar código que compara secretos / MACs / tokens"
  - "al cablear configuración TLS, tamaños de clave o RNG"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "auth-security", "protocol-security"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-131A Rev. 2"
  - "NIST SP 800-57 Part 1 Rev. 5"
  - "OWASP Cryptographic Storage Cheat Sheet"
  - "CWE-327, CWE-338, CWE-916, CWE-208"
---

# Mal uso criptográfico

## Reglas (para agentes de IA)

### SIEMPRE
- Usar la librería criptográfica del lenguaje / plataforma. Python:
  `cryptography`, `secrets`. JavaScript: Web Crypto,
  `crypto.webcrypto`, Node `crypto`. Go: `crypto/*`,
  `golang.org/x/crypto`. Java: JCE / Bouncy Castle. .NET:
  `System.Security.Cryptography`.
- Usar un RNG criptográficamente seguro: Python `secrets.token_bytes`
  / `secrets.token_urlsafe`, JS `crypto.getRandomValues` /
  `crypto.randomBytes`, Go `crypto/rand.Read`, Java `SecureRandom`.
- Hashear contraseñas con un KDF lento ajustado a ~100 ms en hardware
  de producción: **argon2id** (preferido, parámetros RFC 9106:
  m=64 MiB, t=3, p=1), **scrypt** (N=2^17, r=8, p=1), o **bcrypt**
  (cost ≥ 12). Siempre con un salt aleatorio por usuario.
- Cifrar con AEAD (cifrado autenticado): AES-256-GCM,
  ChaCha20-Poly1305 o AES-256-GCM-SIV. Generar un nonce aleatorio
  fresco por cifrado.
- Usar TLS 1.2+ (TLS 1.3 muy preferido). Desactivar TLS 1.0/1.1,
  SSLv3, RC4, 3DES y cifrados de exportación.
- Comparar MACs / firmas / tokens con helpers de tiempo constante:
  `hmac.compare_digest`, `crypto.subtle.timingSafeEqual`,
  `subtle.ConstantTimeCompare`, `MessageDigest.isEqual`,
  `CryptographicOperations.FixedTimeEquals`.
- Para claves asimétricas: RSA ≥ 3072 bits, ECDSA P-256 o P-384,
  Ed25519, X25519.

### NUNCA
- Usar MD5 o SHA-1 para firmas, certificados, almacenamiento de
  contraseñas o autenticación de mensajes. (Siguen siendo válidos para
  usos no-de-seguridad incidentales como ETag / deduplicación de
  archivos si está explícitamente documentado.)
- Usar DES, 3DES, RC4 o Blowfish para código nuevo.
- Usar modo ECB. Usar CBC sin HMAC sobre el ciphertext. Usar CTR/GCM
  con nonce reutilizado.
- Usar hashes sin sal para contraseñas. Usar `sha256(password)` para
  almacenamiento de contraseñas — es un hash rápido; el brute force
  es trivial.
- Usar `Math.random()`, Python `random`, `rand()` en C / Go para
  tokens, IDs, nonces o contraseñas. Son predecibles.
- Hardcodear IVs/nonces, salts o claves. Nunca reutilizar un nonce
  GCM/Poly1305 con la misma clave.
- Comparar secretos con `==`, `===`, `strcmp`, `bytes.Equal` — filtran
  por timing.
- Hacer tu propia criptografía (XOR custom, HMAC custom, Diffie-Hellman
  custom, esquemas de firma custom). Usar primitivas auditadas.

### FALSOS POSITIVOS CONOCIDOS
- MD5 / SHA-1 en contextos no-de-seguridad: cómputo de ETag HTTP,
  deduplicación de contenido, claves de caché para datos no sensibles,
  fingerprinting de fixtures. Anotar estos usos con un comentario
  `// non-security use: ...`.
- Test vectors y valores KAT (Known Answer Test) hardcodean
  intencionadamente IVs, claves y plaintexts — pertenecen a `tests/`
  no a producción.
- Interop legacy: algunos protocolos industriales / gubernamentales
  aún requieren cifrados legacy específicos. Documentar la excepción
  y aislar tras un feature flag.

## Contexto (para humanos)

NIST SP 800-131A Rev. 2 es la hoja de ruta autoritativa del gobierno
de EE. UU. para deprecación de algoritmos; el cheat sheet de
almacenamiento de OWASP es el "hacer estas cosas" práctico. Los modos
de fallo recurrentes son: hash rápido para contraseñas (CWE-916), RNG
predecible para tokens (CWE-338), elección de cifrado rota (CWE-327)
y comparación no-tiempo-constante de secretos (CWE-208).

Los asistentes de IA tienden a reflejar el ejemplo de crypto popular
en Stack Overflow circa 2014, lo que significa mucho
`sha256(password)` y `AES-CBC` con padding manual. Esta skill es el
contrapeso.

## Referencias

- `rules/algorithm_blocklist.json`
- `rules/key_size_minimums.json`
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final).
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) — Crypto roto o riesgoso.
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — Esfuerzo computacional insuficiente para hash de contraseñas.
