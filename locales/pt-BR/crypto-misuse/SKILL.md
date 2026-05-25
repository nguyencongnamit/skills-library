---
id: crypto-misuse
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Uso indevido de criptografia"
description: "Bloquear cifras fracas, RNG previsível, chaves subdimensionadas, uso indevido de slow-hash e comparações não constant-time"
category: prevention
severity: critical
applies_to:
  - "ao gerar código que faz hash / criptografa / assina"
  - "ao gerar código que compara segredos / MACs / tokens"
  - "ao configurar parâmetros de TLS, tamanhos de chave ou RNG"
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

# Uso indevido de criptografia

## Regras (para agentes de IA)

### SEMPRE
- Use a biblioteca criptográfica da linguagem / plataforma. Python:
  `cryptography`, `secrets`. JavaScript: Web Crypto,
  `crypto.webcrypto`, Node `crypto`. Go: `crypto/*`,
  `golang.org/x/crypto`. Java: JCE / Bouncy Castle. .NET:
  `System.Security.Cryptography`.
- Use um RNG criptograficamente seguro: Python `secrets.token_bytes`
  / `secrets.token_urlsafe`, JS `crypto.getRandomValues` /
  `crypto.randomBytes`, Go `crypto/rand.Read`, Java `SecureRandom`.
- Faça hash de senhas com um KDF lento calibrado para ~100 ms em
  hardware de produção: **argon2id** (preferido, parâmetros RFC 9106:
  m=64 MiB, t=3, p=1), **scrypt** (N=2^17, r=8, p=1), ou **bcrypt**
  (cost ≥ 12). Sempre com um salt aleatório por usuário.
- Criptografe com AEAD (criptografia autenticada): AES-256-GCM,
  ChaCha20-Poly1305 ou AES-256-GCM-SIV. Gere um nonce aleatório novo
  por criptografia.
- Use TLS 1.2+ (TLS 1.3 fortemente preferido). Desabilite
  TLS 1.0/1.1, SSLv3, RC4, 3DES e cifras de exportação.
- Compare MACs / assinaturas / tokens com helpers de tempo constante:
  `hmac.compare_digest`, `crypto.subtle.timingSafeEqual`,
  `subtle.ConstantTimeCompare`, `MessageDigest.isEqual`,
  `CryptographicOperations.FixedTimeEquals`.
- Para chaves assimétricas: RSA ≥ 3072 bits, ECDSA P-256 ou P-384,
  Ed25519, X25519.

### NUNCA
- Use MD5 ou SHA-1 para assinaturas, certificados, armazenamento de
  senhas ou autenticação de mensagens. (Permanecem válidos para usos
  incidentais não relacionados à segurança como ETag / deduplicação
  de arquivos se explicitamente documentado.)
- Use DES, 3DES, RC4 ou Blowfish em código novo.
- Use modo ECB. Use CBC sem HMAC sobre o ciphertext. Use CTR/GCM com
  nonce reutilizado.
- Use hashes sem salt para senhas. Use `sha256(senha)` para
  armazenamento de senha — é um hash rápido; brute force é trivial.
- Use `Math.random()`, Python `random`, `rand()` em C / Go para
  tokens, IDs, nonces ou senhas. São previsíveis.
- Hardcode IVs/nonces, salts ou chaves. Nunca reutilize um nonce
  GCM/Poly1305 sob a mesma chave.
- Compare segredos com `==`, `===`, `strcmp`, `bytes.Equal` — vazam
  por timing.
- Faça sua própria criptografia (XOR custom, HMAC custom,
  Diffie-Hellman custom, esquemas de assinatura custom). Use
  primitivas auditadas.

### FALSOS POSITIVOS CONHECIDOS
- MD5 / SHA-1 em contextos não relacionados à segurança: cômputo de
  ETag HTTP, deduplicação de conteúdo, chave de cache para dados não
  sensíveis, fingerprinting de fixtures. Anote esses usos com um
  comentário `// non-security use: ...`.
- Test vectors e valores KAT (Known Answer Test) hardcoded
  intencionalmente fixam IVs, chaves e plaintexts — pertencem a
  `tests/`, não a produção.
- Interop legado: alguns protocolos industriais / governamentais
  ainda exigem cifras legadas específicas. Documente a exceção e
  isole atrás de um feature flag.

## Contexto (para humanos)

NIST SP 800-131A Rev. 2 é o roteiro oficial do governo dos EUA para
depreciação de algoritmos; o cheat sheet de armazenamento da OWASP é
o companheiro prático "faça essas coisas". Os modos de falha
recorrentes são: hash rápido para senhas (CWE-916), RNG previsível
para tokens (CWE-338), escolha de cifra quebrada (CWE-327) e
comparação não-constant-time de segredos (CWE-208).

Assistentes de IA tendem a espelhar o exemplo de crypto popular no
Stack Overflow por volta de 2014, o que significa muito
`sha256(senha)` e `AES-CBC` com padding manual. Esta skill é o
contrapeso.

## Referências

- `rules/algorithm_blocklist.json`
- `rules/key_size_minimums.json`
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final).
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) — Crypto quebrada ou arriscada.
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — Esforço computacional insuficiente para hash de senha.
