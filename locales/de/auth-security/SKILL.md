---
id: auth-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Authentifizierungs- und Autorisierungssicherheit"
description: "JWT, OAuth 2.0 / OIDC, Session-Management, CSRF, Passwort-Hashing und MFA-Durchsetzung"
category: prevention
severity: critical
applies_to:
  - "beim Erzeugen von Login- / Signup- / Passwort-Reset-Flows"
  - "beim Erzeugen von JWT-Ausstellung oder -Verifikation"
  - "beim Erzeugen von OAuth-2.0- / OIDC-Client- oder Server-Code"
  - "beim Verdrahten von Session-Cookies, CSRF-Token, MFA"
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

# Authentifizierungs- und Autorisierungssicherheit

## Regeln (für KI-Agenten)

### IMMER
- Bei JWT-Verifikation den erwarteten Algorithmus festpinnen (`RS256`,
  `EdDSA` oder `ES256`) und `iss`, `aud`, `exp`, `nbf` und `iat` verifizieren.
  `alg=none` und jeden unerwarteten Algorithmus ablehnen.
- Für OAuth-2.0-Public-Clients (SPA / Mobile / CLI) den **Authorization-Code-
  Flow mit PKCE** (S256) verwenden. Nie den Implicit Flow. Nie den
  Resource-Owner-Password-Credentials-Grant.
- Session-Cookies: `Secure; HttpOnly; SameSite=Lax` (oder `Strict` für
  sensible Flows). Das Präfix `__Host-` nutzen, wenn keine Subdomain
  geteilt wird.
- Die Session-ID bei Login und bei Privilegienwechsel rotieren. Die Session
  nur als weiches Signal an den User Agent binden — nie als alleinige Prüfung.
- Passwörter mit argon2id (m=64 MiB, t=3, p=1) und einem zufälligen Salt
  pro Nutzer hashen. Bcrypt cost ≥ 12 oder scrypt N≥2^17 sind akzeptable
  Alternativen für Legacy-Systeme. PBKDF2-SHA256 erfordert ≥ 600.000
  Iterationen (OWASP-2023-Mindestwert).
- Passwortlänge ≥ 12 Zeichen ohne Kompositionsregeln erzwingen; Unicode
  zulassen; Kandidatenpasswörter gegen eine bekannt-geleakte Liste prüfen
  (HIBP / pwned-passwords-k-Anonymity-API).
- Account-Lockout *oder* Rate Limiting für Passwortversuche implementieren
  (NIST SP 800-63B §5.2.2: höchstens 100 Fehlversuche über 30 Tage).
- CSRF-Schutz für zustandsverändernde Anfragen implementieren, die aus
  einer Browser-Session erreichbar sind: Synchronizer Token, Double-Submit-
  Cookie oder `SameSite=Strict` für Hochrisiko-Endpunkte.
- MFA / Step-up für administrative Operationen, Passwortänderungen,
  MFA-Geräteänderungen, Abrechnungsänderungen verlangen.
- Bei OIDC den von dir gesendeten `nonce` gegen den `nonce` im ID-Token
  validieren; `at_hash` / `c_hash` validieren, wenn vorhanden.

### NIE
- `Math.random()` (oder irgendein Nicht-CSPRNG) zum Erzeugen von Session-IDs,
  Reset-Tokens, MFA-Recovery-Codes oder API-Keys verwenden.
- JWT `alg=none` akzeptieren; oder HS256 von einem Client akzeptieren, wenn
  der Aussteller mit RS256 signiert (klassische Algorithmus-Confusion-Attacke).
- Passwörter oder Token-Hashes mit `==` / `strcmp` vergleichen; einen
  Konstant-Zeit-Comparator verwenden.
- Passwörter reversibel speichern (verschlüsselt statt gehasht). Die
  Speicherung muss Einwegfunktion sein.
- Durchsickern lassen, ob Benutzername oder Passwort falsch war. Eine
  generische "invalid credentials"-Meldung zurückgeben.
- Access Tokens, Refresh Tokens oder Session-IDs in URL-Querystrings packen
  — sie leaken in Logs, Referer-Header und Browser-History.
- `localStorage` / `sessionStorage` für langlebige Refresh Tokens nutzen.
  HttpOnly-Cookies verwenden.
- Client-gelieferten Rollen / Claims auf der API-Schicht vertrauen — das
  authentifizierte Subjekt neu ableiten und die Autorisierung server-seitig
  bei jeder Anfrage nachschlagen.
- Langlebige (>1 Stunde) Access Tokens ausstellen; sich auf Refresh Tokens
  mit Rotation stützen.
- Den Implicit Flow oder den Password Grant verwenden.

### BEKANNTE FALSCH-POSITIVE
- Service-zu-Service-Tokens mit langen TTLs sind manchmal akzeptabel, wenn
  sie in einem Secret Manager gespeichert sind und an eine spezifische
  Workload-Identität gebunden wurden.
- Lokale Dev-"Magic-Link"-Auth ohne Passwort-Hashing für ephemere Dev-User
  ist okay, wenn sie hinter einer Env-Flag gegated und in Prod deaktiviert
  ist.
- Tokens in URL-Querys sind an *einer* Stelle tolerierbar — beim OAuth-
  Authorization-Code-Rückkanal — weil der Wert kurzlebig und einmalig ist.

## Kontext (für Menschen)

Authentifizierungsfehler tauchen konstant in OWASP Top 10 auf
(A07:2021 — Identification and Authentication Failures). Die üblichen Modi
sind: schwache Passwortspeicherung, vorhersehbare Tokens, fehlende MFA,
JWT-Fehlkonfiguration und Session-Fixation. RFC 9700 (OAuth 2.0 Security
BCP) und NIST SP 800-63B sind die autoritativen Referenzen für das Rezept.

KI-Assistenten neigen dazu, "funktioniert in Dev"-Auth auszuliefern: HS256-
JWTs mit hartkodierten Secrets, `bcrypt.hash` mit Default-Cost 10, kein
PKCE, Tokens in localStorage. Dieser Skill fängt jedes davon ab.

## Referenzen

- `rules/jwt_safe_config.json`
- `rules/oauth_flows.json`
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
