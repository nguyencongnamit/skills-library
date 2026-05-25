---
id: graphql-security
language: de
source_revision: "4c215e6f"
version: "1.0.0"
title: "GraphQL-Sicherheit"
description: "GraphQL-APIs verteidigen: Tiefen-/Komplexitätslimits, Introspection in Produktion, Batching-/Aliasing-Missbrauch, feldweise Autorisierung, Persisted Queries"
category: prevention
severity: high
applies_to:
  - "beim Erzeugen von GraphQL-Schemata, -Resolvern oder -Serverkonfig"
  - "beim Verdrahten von Authentifizierung/Autorisierung an einen GraphQL-Endpoint"
  - "beim Hinzufügen eines öffentlichen GraphQL-API-Gateways"
  - "beim Review der Exposition des /graphql-Endpoints"
languages: ["javascript", "typescript", "python", "go", "java", "kotlin", "csharp", "ruby"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP GraphQL Cheat Sheet"
  - "CWE-400: Uncontrolled Resource Consumption"
  - "Apollo GraphQL Production Checklist"
  - "graphql-armor (Escape technologies)"
---

# GraphQL-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Eine maximale **Query-Tiefe** (typisch: 7–10) und **Query-
  Komplexität** (Cost) am Server erzwingen. Eine 5 Ebenen
  geschachtelte Query gegen eine Many-to-Many-Beziehung kann
  Milliarden von Knoten zurückgeben; ohne Cost-Limit legt ein
  Client die Datenbank lahm.
- **Introspection** in Produktion deaktivieren. Introspection
  macht Aufklärung trivial; legitime Clients haben das Schema per
  Codegen oder `.graphql`-Artefakt eingebacken.
- **Persisted Queries** (in einer Allowlist erlaubte Operation-
  Hashes) für jede traffic-starke / öffentliche API verwenden.
  Anonymes beliebiges GraphQL ist das GraphQL-Äquivalent von
  `eval(req.body)`.
- **Feldweise Autorisierung** in den Resolvern anwenden, nicht nur
  am Endpoint. GraphQL aggregiert viele Felder zu einer HTTP-
  Antwort — ein einzelnes fehlendes `@auth` an einem sensiblen
  Feld leakt Daten in der ganzen Query.
- Die Anzahl der **Aliases** pro Request limitieren (typisch: 15)
  und die Anzahl der **Operationen pro Batch** (typisch: 5).
  Apollo / Relay erlauben beide gebatchte Queries — ohne Limits
  ist das ein N-Seiten-der-API-Amplifikations-Primitiv.
- **Zirkuläre Fragment-**Definitionen früh ablehnen (die meisten
  Server tun das, eigene Executors nicht). Ein selbstreferenzieren-
  des Fragment verursacht exponentielle Parse-Zeit-Kosten.
- Generische Fehler an Clients zurückgeben
  (`INTERNAL_SERVER_ERROR`, `UNAUTHORIZED`) und Stack-Traces /
  SQL-Snippets nur in Server-Logs routen. Die Apollo-Default-
  Errors leaken Schema- und Query-Internals.
- Ein Request-Size-Limit (typisch: 100 KiB) und ein Request-
  Timeout (typisch: 10 s) auf der HTTP-Schicht vor dem GraphQL-
  Server setzen. Eine 1-MiB-GraphQL-Query hat keinen legitimen
  Zweck.

### NIE
- `/graphql`-Introspection an einem Produktions-Endpoint
  exponieren. Das GraphQL-Playground (GraphiQL, Apollo Sandbox)
  muss in Produktions-Builds ebenfalls deaktiviert sein.
- Der Tiefe / Komplexität einer Query vertrauen, weil "unsere
  Clients schicken nur wohlgeformte Queries". Jeder Angreifer kann
  einen Request an `/graphql` von Hand basteln.
- Direktiven `@skip(if: ...)` / `@include(if: ...)` erlauben, um
  Autorisierungs-Checks zu steuern. Direktiven laufen in den
  meisten Executors nach der Autorisierung, aber custom
  Direktiven-Reihenfolgen haben Authz-Bypasses produziert.
- N+1-Muster in Resolvern implementieren (eine DB-Query pro
  Parent-Record). Stattdessen einen DataLoader oder join-basiertes
  Fetch verwenden. N+1 ist Performance-Bug und DoS-Amplifier
  zugleich.
- File-Uploads via GraphQL-Multipart (`apollo-upload-server`,
  `graphql-upload`) ohne Grössenlimits, MIME-Validierung und
  Out-of-Band-Virenscan zulassen. Der CVE-2020-7754 aus 2020
  (`graphql-upload`) zeigte, wie ein fehlerhafter Multipart den
  Server abstürzen lässt.
- GraphQL-Antworten allein per URL cachen. POST `/graphql`
  verwendet immer dieselbe URL; der Cache muss nach Operation-
  Hash + Variablen + Auth-Claims schlüsseln, um Cross-Tenant-Leaks
  zu vermeiden.
- Mutations exponieren, die untrusted JSON-`input:`-Objekte
  entgegennehmen, ohne Schema-Validierung. GraphQL-Typen sind auf
  der Schema-Ebene verpflichtend, aber `JSON`- / `Scalar`-Typen
  hebeln das vollständig aus.

### BEKANNTE FALSCH-POSITIVE
- Interne Admin-GraphQL-Endpoints hinter einer authentifizierten
  VPN dürfen Introspection legitim eingeschaltet lassen für
  Developer-Ergonomie.
- Statisch zugelassene Persisted Queries machen Tiefen- /
  Komplexitäts-Checks für diese Operationen redundant — die
  Checks für jede Operation behalten, die nicht in der Allowlist
  steht (also Operationen über ein `disabled`-Flag).
- Öffentliche, nur-lesende Daten-APIs dürfen sehr hohe Cost-Limits
  verwenden, wenn Caching auf der CDN-Schicht aggressiv
  konfiguriert ist; der Trade-Off ist pro Endpoint dokumentiert.

## Kontext (für Menschen)

GraphQL gibt Clients eine Query-Sprache. Diese Sprache ist in der
Praxis Turing-vollständig — Tiefe, Aliasing, Fragmente und Unions
kombinieren sich zu nahezu beliebiger Berechnung gegen den
Resolver-Graph. `/graphql` als einzelnen Endpoint mit einfachen
WAF- / Rate-Limit-Kontrollen zu behandeln ist unzureichend.

Die GraphQL-Incident-Ära 2022-2024 (Hyatt, Slack-Research aus
Apollo, mehrere Account-Takeover-via-Batching-Fälle) drehten sich
alle entweder um fehlende feldweise Autorisierung oder fehlende
Cost-Analyse. graphql-armor (Escape) und Apollos eingebaute
Validierungs-Regeln liefern für die meisten davon mittlerweile
Off-the-shelf-Middleware — verwendet sie.

## Referenzen

- `rules/graphql_safe_config.json`
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- [Apollo Production Checklist](https://www.apollographql.com/docs/apollo-server/security/production-checklist/).
- [graphql-armor](https://escape.tech/graphql-armor/).
