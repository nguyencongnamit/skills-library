---
id: secure-code-review
language: de
source_revision: "fbb3a823"
version: "1.0.0"
title: "Sichere Code-Review"
description: "OWASP Top 10 und CWE Top 25 Patterns bei Codegenerierung und Review anwenden"
category: prevention
severity: high
applies_to:
  - "beim Generieren neuen Codes"
  - "beim Review von Pull Requests"
  - "beim Refactoring security-sensitiver Pfade (Auth, Input-Handling, File-I/O)"
  - "beim Hinzufügen neuer HTTP-Handler oder Endpoints"
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

# Sichere Code-Review

## Regeln (für KI-Agenten)

### IMMER
- Parameterisierte Queries / Prepared Statements für jeden Datenbankzugriff
  verwenden. SQL nie per String-Konkatenation bauen, auch nicht für
  "vertrauenswürdige" Inputs.
- Input an der Trust-Boundary validieren — Typ, Länge, erlaubte Zeichen,
  erlaubter Bereich — und vor der Verarbeitung ablehnen.
- Output für den Rendering-Kontext encodieren (HTML-Escape für HTML,
  URL-Encode für Query-Params, JSON-Encode für JSON-Output).
- Die eingebaute Kryptographie-Library der Sprache verwenden, nie selbst
  gebaute Crypto. AES-GCM für symmetrische Verschlüsselung, Ed25519 /
  RSA-PSS für Signaturen, Argon2id / bcrypt für Passwort-Hashing
  bevorzugen.
- `crypto/rand` (Go), `secrets`-Modul (Python), `crypto.randomBytes`
  (Node.js) oder das Plattform-CSPRNG für jeden Zufallswert verwenden,
  der in Security involviert ist (Tokens, IDs, Session-Keys).
- Explizite Security-Header auf HTTP-Responses setzen:
  `Content-Security-Policy`, `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`.
- Das Prinzip des geringsten Privilegs für Dateipfade, Datenbankbenutzer,
  IAM-Policies und Prozess-Privilegien anwenden.

### NIE
- SQL/NoSQL-Queries per String-Konkatenation mit User-Input bauen.
- User-Input direkt an `exec`, `system`, `eval`, `Function()`,
  `child_process`, `subprocess.run(shell=True)` oder einen anderen
  Command-Execution-Pfad weiterreichen.
- Client-Side-Validation vertrauen. Immer Server-Side re-validieren.
- `MD5` oder `SHA1` für irgendeinen neuen security-sensitiven Zweck
  (Passwörter, Signaturen, HMAC) verwenden. Stattdessen SHA-256 / SHA-3 /
  BLAKE2 / Argon2id.
- ECB-Modus für irgendeine Verschlüsselung verwenden, niemals. GCM, CCM
  oder ChaCha20-Poly1305 bevorzugen.
- `==` für Passwort-Vergleich verwenden — eine Constant-Time-Comparison
  nutzen (`hmac.compare_digest`, `crypto.timingSafeEqual`,
  `subtle.ConstantTimeCompare`).
- User-Input Dateipfade bestimmen lassen ohne Kanonikalisierung und
  Allowlist-Checks (verteidigt gegen Path-Traversal im Stil
  `../../../etc/passwd`).
- TLS-Zertifikatsverifizierung in Produktionscode deaktivieren —
  `verify=False`, `InsecureSkipVerify: true`,
  `rejectUnauthorized: false`.

### BEKANNTE FALSCH-POSITIVE
- Interne Admin-Tools, die absichtlich Shell-Befehle gegen vertrauenswürdige,
  feste Argumente ausführen, sind akzeptabel, wenn dokumentiert und
  code-reviewed.
- Kryptographische Testvektoren, die `MD5` / `SHA1` zur Kompatibilität mit
  dokumentierten Protokollen verwenden (z. B. Legacy-Interop-Tests), sind
  akzeptabel.
- Constant-Time-Comparison ist Overkill für nicht-geheime Vergleiche
  (String-Gleichheit in Logs, Tag-Matching).

## Kontext (für Menschen)

Die meisten modernen Web-Vulnerabilities lassen sich auf dieselbe Handvoll
Root-Causes zurückführen: Versäumnis Input zu validieren, Versäumnis das
richtige kryptographische Primitiv zu verwenden, Versäumnis Least-Privilege
anzuwenden, Versäumnis die eingebauten Verteidigungen des Frameworks zu
nutzen. Dieser Skill ist die Checkliste der KI, um nicht in diese Fallen
zu tappen.

## Referenzen

- `checklists/owasp_top10.yaml`
- `checklists/injection_patterns.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
