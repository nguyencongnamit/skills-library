---
id: crypto-misuse
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Mauvais usage cryptographique"
description: "Bloquer les chiffrements faibles, les RNG prévisibles, les clés trop petites, le mauvais usage des slow-hash et les comparaisons non constant-time"
category: prevention
severity: critical
applies_to:
  - "lors de la génération de code qui hache / chiffre / signe"
  - "lors de la génération de code qui compare des secrets / MACs / tokens"
  - "lors du câblage des réglages TLS, des tailles de clé ou du RNG"
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

# Mauvais usage cryptographique

## Règles (pour les agents IA)

### TOUJOURS
- Utiliser la bibliothèque cryptographique du langage / de la
  plateforme. Python : `cryptography`, `secrets`. JavaScript : Web
  Crypto, `crypto.webcrypto`, Node `crypto`. Go : `crypto/*`,
  `golang.org/x/crypto`. Java : JCE / Bouncy Castle. .NET :
  `System.Security.Cryptography`.
- Utiliser un RNG cryptographiquement sûr : Python
  `secrets.token_bytes` / `secrets.token_urlsafe`, JS
  `crypto.getRandomValues` / `crypto.randomBytes`, Go
  `crypto/rand.Read`, Java `SecureRandom`.
- Hacher les mots de passe avec un KDF lent calibré pour ~100 ms sur
  le matériel de production : **argon2id** (préféré, paramètres
  RFC 9106 : m=64 MiB, t=3, p=1), **scrypt** (N=2^17, r=8, p=1) ou
  **bcrypt** (cost ≥ 12). Toujours avec un sel aléatoire par
  utilisateur.
- Chiffrer en AEAD (chiffrement authentifié) : AES-256-GCM,
  ChaCha20-Poly1305 ou AES-256-GCM-SIV. Générer un nonce aléatoire
  frais par chiffrement.
- Utiliser TLS 1.2+ (TLS 1.3 fortement préféré). Désactiver
  TLS 1.0/1.1, SSLv3, RC4, 3DES et les chiffrements d'export.
- Comparer les MAC / signatures / tokens avec des helpers à temps
  constant : `hmac.compare_digest`, `crypto.subtle.timingSafeEqual`,
  `subtle.ConstantTimeCompare`, `MessageDigest.isEqual`,
  `CryptographicOperations.FixedTimeEquals`.
- Pour les clés asymétriques : RSA ≥ 3072 bits, ECDSA P-256 ou P-384,
  Ed25519, X25519.

### JAMAIS
- Utiliser MD5 ou SHA-1 pour les signatures, certificats, stockage de
  mot de passe ou authentification de message. (Restent valides pour
  des usages incidents non liés à la sécurité comme ETag /
  déduplication de fichiers si explicitement documenté.)
- Utiliser DES, 3DES, RC4 ou Blowfish pour du nouveau code.
- Utiliser le mode ECB. Utiliser CBC sans HMAC sur le ciphertext.
  Utiliser CTR/GCM avec un nonce réutilisé.
- Utiliser des hashes non salés pour les mots de passe. Utiliser
  `sha256(password)` pour le stockage des mots de passe — c'est un
  hash rapide ; le brute force est trivial.
- Utiliser `Math.random()`, Python `random`, `rand()` en C / Go pour
  des tokens, IDs, nonces ou mots de passe. Ils sont prévisibles.
- Hardcoder les IV/nonces, sels ou clés. Ne jamais réutiliser un nonce
  GCM/Poly1305 sous la même clé.
- Comparer les secrets avec `==`, `===`, `strcmp`, `bytes.Equal` — ils
  fuient par timing.
- Rouler votre propre crypto (XOR custom, HMAC custom, Diffie-Hellman
  custom, schémas de signature custom). Utiliser des primitives
  auditées.

### FAUX POSITIFS CONNUS
- MD5 / SHA-1 dans des contextes non liés à la sécurité : calcul de
  ETag HTTP, déduplication de contenu, clé de cache pour données non
  sensibles, fingerprinting de fixtures. Annoter ces usages avec un
  commentaire `// non-security use: ...`.
- Les test vectors et valeurs KAT (Known Answer Test) hardcodent
  intentionnellement les IV, clés et plaintexts — ils appartiennent à
  `tests/`, pas à la production.
- Interop legacy : certains protocoles industriels / gouvernementaux
  exigent encore des chiffrements legacy spécifiques. Documenter
  l'exception et isoler derrière un feature flag.

## Contexte (pour les humains)

NIST SP 800-131A Rev. 2 est la feuille de route officielle du
gouvernement US pour la dépréciation des algorithmes ; le cheat sheet
de stockage d'OWASP est le compagnon pratique "faites ces choses". Les
modes de défaillance récurrents sont : hash rapide pour mots de passe
(CWE-916), RNG prévisible pour tokens (CWE-338), mauvais choix de
chiffrement (CWE-327), et comparaison non constant-time des secrets
(CWE-208).

Les assistants IA ont tendance à refléter l'exemple crypto populaire
sur Stack Overflow vers 2014, ce qui veut dire beaucoup de
`sha256(password)` et `AES-CBC` avec padding manuel. Cette skill est
le contrepoids.

## Références

- `rules/algorithm_blocklist.json`
- `rules/key_size_minimums.json`
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final).
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) — Crypto cassé ou risqué.
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — Effort computationnel insuffisant pour hash de mot de passe.
