---
id: error-handling-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Sicherheit beim Error-Handling"
description: "Keine Stack-Traces / SQL / Pfade / Framework-Versionen in Client-Responses; generische Fehler nach aussen, strukturierte Fehler in den Logs"
category: prevention
severity: medium
applies_to:
  - "beim Erzeugen von HTTP- / GraphQL- / RPC-Error-Handlern"
  - "beim Erzeugen von Exception- / Panic- / Rescue-Blöcken"
  - "beim Verdrahten von Framework-Default-Error-Pages"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 900
  full: 1900
rules_path: "rules/"
related_skills: ["api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Error Handling Cheat Sheet"
  - "CWE-209 — Generation of Error Message Containing Sensitive Information"
  - "CWE-754 — Improper Check for Unusual or Exceptional Conditions"
---

# Sicherheit beim Error-Handling

## Regeln (für KI-Agenten)

### IMMER
- Exceptions an der Grenze fangen (HTTP-Handler, RPC-Methode,
  Message-Consumer). Sie serverseitig mit vollständigem Kontext
  loggen; einen bereinigten Fehler nach aussen zurückgeben.
- Externe Error-Responses enthalten: einen stabilen Error-Code, eine
  kurze menschenlesbare Message und eine Correlation- / Request-ID.
  Sie enthalten nie: Stack-Trace, SQL-Fragment, Filesystem-Pfad,
  internen Hostnamen, Framework-Version-Banner.
- Fehler auf der passenden Stufe loggen: `ERROR` / `WARN` für
  handlungsrelevante Fehler; `INFO` für erwartete Business-Outcomes;
  `DEBUG` für Diagnose-Detail (und nur, wenn explizit aktiviert).
- Uniforme Error-Responses über die gesamte API-Oberfläche
  zurückgeben — gleiche Form, gleiches Set an Codes — damit
  Angreifer aus Error-Variation kein Verhalten ableiten können
  (z. B. Login: gleiche Message und gleiches Timing für "falscher
  Username" vs. "falsches Password").
- Framework-Default-Error-Pages in Produktion deaktivieren
  (`app.debug = False` / `Rails.env.production?` /
  `Environment=Production` / `DEBUG=False`). Durch eine 5xx-Seite
  ersetzen, die nur die Correlation-ID zurückgibt.
- Einen zentralen Error-Render-Helper nutzen, damit die
  Sanitisierungs-Regeln an einer Stelle leben, nicht dupliziert.

### NIE
- `traceback.format_exc()`, `e.toString()`, `printStackTrace()`,
  `panic` oder Framework-Debug-Pages in Produktion an den Client
  rendern.
- SQL-Queries / -Parameter in Error-Messages echoen —
  `IntegrityError: duplicate key value violates unique constraint
  "users_email_key"` verrät dem Angreifer Tabellen- und
  Spaltennamen.
- Existenz-Information leaken: `User not found` vs `Invalid
  password` erlaubt Account-Enumeration. Eine einzige Message für
  beides verwenden.
- Filesystem-Pfade (`/var/www/app/src/handlers.py`) oder Version-
  Banner (`X-Powered-By: Express/4.17.1`) leaken.
- `try / except: pass` als Error-Handling behandeln; entweder ist
  die Exception erwartet (loggen + weiter) oder nicht (propagieren
  lassen).
- 4xx-Error-Responses zur Validierung der Input-Form nutzen — Bots
  iterieren über Parameter und nutzen den Response-Body, um das
  Schema zu lernen. Uniformes 400 plus Correlation-ID für
  malformeden Input zurückgeben.
- Volle Fehler-Details (inkl. PII) an Drittanbieter-Error-Tracker
  ohne Scrubber schicken. `password`, `Authorization`, `Cookie`,
  `Set-Cookie`, `token`, `secret` und gängige PII-Patterns
  redigieren.

### BEKANNTE FALSCH-POSITIVE
- Entwickler-Error-Pages auf `localhost` / `*.local` sind ok.
- Eine Handvoll API-Endpoints (Debug, Admin, internes RPC) darf
  legitim mehr Detail zurückgeben; sie müssen authentifizierte,
  autorisierte Caller verlangen und nie aus dem Internet erreichbar
  sein.
- Health-Checks und CI-Smoke-Tests legen Detail absichtlich offen,
  wenn sie aus dem Cluster aufgerufen werden.

## Kontext (für Menschen)

CWE-209 ist kleiner Text mit grosser Wirkung: so kommen Angreifer
vom "dieser Service existiert" zu "dieser Service läuft Spring 5.2
auf Tomcat 9 mit einer PostgreSQL-Tabelle `users` und Column
`email_normalized`". Jedes zusätzliche Detail in der Error-Message
senkt die Kosten des nächsten Angriffs.

Dieser Skill ist bewusst eng zugeschnitten und ergänzt
`logging-security` (die *Log*-Seite derselben Operation) und
`api-security` (die Response-Form).

## Referenzen

- `rules/error_response_template.json`
- `rules/redaction_patterns.json`
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
