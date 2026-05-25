---
id: api-security
language: de
source_revision: "fbb3a823"
version: "1.0.0"
title: "API-Sicherheit"
description: "OWASP-API-Top-10-Muster auf Authentifizierung, Autorisierung und Eingabevalidierung anwenden"
category: prevention
severity: high
applies_to:
  - "beim Erzeugen von HTTP-Handlern"
  - "beim Erzeugen von GraphQL-Resolvern"
  - "beim Erzeugen von gRPC-Service-Methoden"
  - "beim Review von API-Endpunkt-Änderungen"
languages: ["*"]
token_budget:
  minimal: 500
  compact: 750
  full: 2300
rules_path: "checklists/"
related_skills: ["secure-code-review", "secret-detection"]
last_updated: "2026-05-12"
sources:
  - "OWASP API Security Top 10 2023"
  - "OWASP Authentication Cheat Sheet"
  - "OAuth 2.0 Security Best Current Practice (RFC 9700)"
---

# API-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Authentifizierung auf jedem nicht öffentlichen Endpunkt verlangen. Standardmäßig
  authentifiziert; genuin öffentliche Routen werden explizit annotiert.
- Autorisierung auf Objektebene durchsetzen — bestätigen, dass das authentifizierte
  Subjekt tatsächlich Zugriff auf die angeforderte Ressourcen-ID hat, nicht nur,
  dass es angemeldet ist (das verhindert die OWASP-API1-Klasse BOLA / IDOR).
- Alle Request-Eingaben gegen ein explizites Schema validieren (JSON Schema,
  Pydantic, Zod, struct tags von validator/v10). Früh ablehnen; nie nicht
  vertrauenswürdige Eingaben tiefer durchreichen.
- Rate Limits auf Routen-Ebene für Authentifizierungs-Endpunkte, Passwort-Reset
  und jede teure Operation durchsetzen.
- Kurzlebige Access Token (≤ 1 Stunde) mit Refresh Token verwenden, nicht
  langlebige Bearer Token.
- Generische Fehlermeldungen nach außen zurückgeben (`invalid credentials`) und
  Details intern loggen — nicht durchsickern lassen, ob Benutzername oder
  Passwort falsch war.
- `Cache-Control: no-store` in Antworten setzen, die personenbezogene oder
  sensible Daten enthalten.

### NIE
- Aufsteigende ganzzahlige IDs in URLs für mandantenübergreifend zugängliche
  Ressourcen verwenden. UUIDs oder nicht erratbare opake IDs verwenden.
- `Authorization`-Headern vertrauen, ohne Signatur und Ablauf zu verifizieren.
- JWTs mit Algorithmus `none` akzeptieren. Den erwarteten Algorithmus bei der
  Verifikation fest anpinnen.
- Request-Bodies per Mass-Assignment direkt an ORM-Modelle übergeben
  (`User(**request.json)`) — das ermöglicht Privilege Escalation, wenn das
  Modell Admin-Felder hat, die der Benutzer nicht kontrollieren sollte.
- CSRF-Schutz auf zustandsverändernden Endpunkten deaktivieren, die von Browsern
  genutzt werden.
- Stacktraces oder Framework-Fehlerseiten in Produktion an den Client zurückgeben.
- `HTTP GET` für irgendeine zustandsverändernde Operation verwenden — GET muss
  sicher und idempotent sein.

### BEKANNTE FALSCH-POSITIVE
- Öffentliche Marketing-Seiten-Endpunkte, die anonymen Traffic ausliefern, haben
  legitim keine Authentifizierung und keine Rate Limits jenseits des Load
  Balancers.
- Aufsteigende IDs in Pfaden sind in Ordnung für genuin öffentliche, nicht
  mandantengebundene Ressourcen (z. B. Blog-Post-Slugs, öffentlicher
  Produktkatalog).
- Health-Check-Endpunkte (`/healthz`, `/ready`) umgehen Authentifizierung
  absichtlich.

## Kontext (für Menschen)

Die OWASP API Top 10 unterscheiden sich von den Web Top 10 vor allem, weil APIs
schwächere Defaults haben: CSRF wird oft übersprungen, Objekt-IDs werden direkt
exponiert, und es wird tendenziell client-seitig vom Entwickler bereitgestelltem
Zustand vertraut. Dieser Skill kodifiziert die häufigsten Fehler mit hohem
Impact.

## Referenzen

- `checklists/auth_patterns.yaml`
- `checklists/input_validation.yaml`
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
