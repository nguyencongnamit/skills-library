---
id: crypto-misuse
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Krypto-Fehlbenutzung"
description: "Schwache Cipher, vorhersagbare RNG, zu kleine Keys, Slow-Hash-Misbrauch und non-constant-time Vergleiche blockieren"
category: prevention
severity: critical
applies_to:
  - "beim Erzeugen von Code, der hasht / verschlüsselt / signiert"
  - "beim Erzeugen von Code, der Secrets / MACs / Tokens vergleicht"
  - "beim Verdrahten von TLS-Settings, Key-Größen oder RNG"
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

# Krypto-Fehlbenutzung

## Regeln (für KI-Agenten)

### IMMER
- Die Krypto-Bibliothek der Sprache / Plattform verwenden. Python:
  `cryptography`, `secrets`. JavaScript: Web Crypto,
  `crypto.webcrypto`, Node `crypto`. Go: `crypto/*`,
  `golang.org/x/crypto`. Java: JCE / Bouncy Castle. .NET:
  `System.Security.Cryptography`.
- Einen kryptographisch sicheren RNG verwenden: Python
  `secrets.token_bytes` / `secrets.token_urlsafe`, JS
  `crypto.getRandomValues` / `crypto.randomBytes`, Go
  `crypto/rand.Read`, Java `SecureRandom`.
- Passwörter mit einem langsamen KDF hashen, abgestimmt auf ~100 ms
  auf Production-Hardware: **argon2id** (bevorzugt, RFC-9106-
  Parameter: m=64 MiB, t=3, p=1), **scrypt** (N=2^17, r=8, p=1) oder
  **bcrypt** (Cost ≥ 12). Immer mit einem zufälligen Salt pro Nutzer.
- Mit AEAD (authenticated encryption) verschlüsseln: AES-256-GCM,
  ChaCha20-Poly1305 oder AES-256-GCM-SIV. Pro Verschlüsselung einen
  frischen zufälligen Nonce erzeugen.
- TLS 1.2+ verwenden (TLS 1.3 stark bevorzugt). TLS 1.0/1.1, SSLv3,
  RC4, 3DES und Export-Cipher deaktivieren.
- MACs / Signaturen / Tokens mit Constant-Time-Helpern vergleichen:
  `hmac.compare_digest`, `crypto.subtle.timingSafeEqual`,
  `subtle.ConstantTimeCompare`, `MessageDigest.isEqual`,
  `CryptographicOperations.FixedTimeEquals`.
- Für asymmetrische Keys: RSA ≥ 3072 Bit, ECDSA P-256 oder P-384,
  Ed25519, X25519.

### NIE
- MD5 oder SHA-1 für Signaturen, Zertifikate, Passwort-Speicherung
  oder Message-Authentifizierung verwenden. (Bleiben gültig für
  inzidentelle Non-Security-Nutzungen wie ETag /
  Datei-Deduplikation, sofern explizit dokumentiert.)
- DES, 3DES, RC4 oder Blowfish für neuen Code verwenden.
- ECB-Modus verwenden. CBC ohne HMAC über den Ciphertext verwenden.
  CTR/GCM mit wiederverwendetem Nonce verwenden.
- Ungesalzene Hashes für Passwörter verwenden.
  `sha256(password)` für Passwort-Speicherung verwenden — es ist ein
  Fast-Hash; Brute Force ist trivial.
- `Math.random()`, Python `random`, `rand()` in C / Go für Tokens,
  IDs, Nonces oder Passwörter verwenden. Sind vorhersagbar.
- IVs/Nonces, Salts oder Keys hardcoden. Niemals einen GCM/Poly1305-
  Nonce unter demselben Key wiederverwenden.
- Secrets mit `==`, `===`, `strcmp`, `bytes.Equal` vergleichen —
  diese leaken über Timing.
- Eigene Krypto bauen (Custom-XOR, Custom-HMAC, Custom-Diffie-Hellman,
  Custom-Signaturschemata). Auditiierte Primitives verwenden.

### BEKANNTE FALSCH-POSITIVE
- MD5 / SHA-1 in Non-Security-Kontexten: HTTP-ETag-Berechnung,
  Content-Deduplikation, Cache-Keying für nicht-sensible Daten,
  Fixture-Fingerprinting. Diese Verwendungen mit einem
  `// non-security use: ...` Kommentar annotieren.
- Testvektoren und KAT-Werte (Known Answer Test) hardcoden absichtlich
  IVs, Keys und Plaintexts — gehören in `tests/`, nicht in
  Production.
- Legacy-Interop: einige Industrie-/Behörden-Protokolle verlangen
  noch spezifische Legacy-Cipher. Ausnahme dokumentieren und hinter
  einem Feature-Flag isolieren.

## Kontext (für Menschen)

NIST SP 800-131A Rev. 2 ist die autoritative US-Regierungs-
Deprecation-Roadmap für Algorithmen; das OWASP-Storage-Cheat-Sheet ist
das praktische "mach diese Dinge"-Begleitdokument. Wiederkehrende
Failure-Modes: Fast-Hash für Passwörter (CWE-916), vorhersagbarer RNG
für Tokens (CWE-338), kaputte Cipher-Wahl (CWE-327) und
non-constant-time Vergleich von Secrets (CWE-208).

KI-Assistenten neigen dazu, das auf Stack Overflow circa 2014 populäre
Krypto-Beispiel zu spiegeln — was viel `sha256(password)` und
`AES-CBC` mit manuellem Padding bedeutet. Dieser Skill ist das
Gegengewicht.

## Referenzen

- `rules/algorithm_blocklist.json`
- `rules/key_size_minimums.json`
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final).
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html).
- [CWE-327](https://cwe.mitre.org/data/definitions/327.html) — Gebrochene oder riskante Krypto.
- [CWE-916](https://cwe.mitre.org/data/definitions/916.html) — Unzureichender Rechenaufwand für Passwort-Hash.
