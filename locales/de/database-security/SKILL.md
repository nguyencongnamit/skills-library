---
id: database-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Datenbank-Sicherheit"
description: "SQL-Injection, ORM-Misbrauch und Credential-Leaks verhindern; Least-Privilege-DB-User und sichere Migrationen erzwingen"
category: prevention
severity: critical
applies_to:
  - "beim Erzeugen von SQL oder Raw-Query-Strings"
  - "beim Erzeugen von ORM-Modellcode oder Queries"
  - "beim Erzeugen von Datenbank-Migration-Files"
  - "beim Verdrahten von Connection-Strings oder Pooling"
languages: ["sql", "python", "javascript", "typescript", "go", "ruby", "java", "kotlin", "csharp"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2500
rules_path: "rules/"
related_skills: ["secret-detection", "api-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SQL Injection Prevention Cheat Sheet"
  - "OWASP Database Security Cheat Sheet"
  - "CWE-89: Improper Neutralization of Special Elements in an SQL Command"
  - "CIS PostgreSQL / MySQL Benchmarks"
---

# Datenbank-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Parametrisierte Queries / Prepared Statements für jegliches SQL
  verwenden, das user-kontrollierte Werte berührt. Werte als Parameter
  übergeben, nie via String-Concat oder -Formatting (`%s`, `+`,
  Template Literals).
- Die sichere Query-API des ORM verwenden. In SQLAlchemy:
  `session.execute(text(":id"), {"id": user_id})`. In Django:
  ORM-Methoden, `Model.objects.filter(...)`. In Sequelize / Prisma /
  SQLAlchemy Core: `.where({ ... })`-Builder. In Go:
  `db.QueryContext(ctx, "select ... where id = $1", id)`.
- Validieren, dass Identifier-Spalten / Tabellennamen — die nicht
  parametrisiert werden können — aus einer hardcodierten Allowlist
  kommen, nicht aus User-Input.
- Einen dedizierten Datenbank-User pro Anwendung mit den minimal
  nötigen Grants verwenden. Web-Apps, die nur lesen, sollten kein
  `INSERT`/`UPDATE`/`DELETE` haben. Migration-Jobs laufen als
  separater, `DDL`-fähiger User.
- Row-Level Security aktivieren (Postgres `CREATE POLICY` / Supabase
  RLS / Azure SQL RLS) für Multi-Tenant-Tabellen und den Tenant-Kontext
  pro Session setzen.
- DB-Credentials aus einem Secret Manager oder beim Start injizierter
  Env-Var ziehen — nie aus einer eingecheckten `database.yml` /
  `.env`. Nach Zeitplan rotieren.
- TLS zur Datenbank verwenden (`sslmode=require` für Postgres,
  `requireSSL=true` für MySQL, verschlüsselte Verbindung für MSSQL).
  CA pinnen, wo der Driver das unterstützt.
- Connection-Pooling hat eine Max-Größe, die innerhalb der DB-
  `max_connections` passt, mit gesundem Back-Pressure auf die App.

### NIE
- User-Input in SQL concatenieren: `"SELECT * FROM users WHERE name='"
  + name + "'"`. Auch wenn du selbst "escapest" — Driver escapen
  korrekt nur, wenn du via Parameter-API bindest.
- ORM-Raw-Query-Methoden (`.raw()`, `.objects.raw()`,
  `.query(text(...))`) mit f-String-Interpolation von User-Input
  verwenden.
- Anwendungs-Workloads als Datenbank-Superuser / `root` / `postgres` /
  `sa` laufen lassen. Einen Service-User anlegen.
- TLS zur Datenbank deaktivieren (`sslmode=disable`, `useSSL=false`).
- Secrets, PII oder große Blobs in JSON-Spalten speichern, ohne
  Encryption-at-Rest und Key-Rotation-Plan.
- Destruktive Migrationen (DROP TABLE, DROP COLUMN, ALTER COLUMN
  Type-Changes auf befüllten Tabellen) inline mit Deploys ohne
  Expand–Contract-Plan und verifiziert-restorebaren Backup fahren.
- Einen internet-exposed Datenbank-Listener ohne Allowlist binden;
  Datenbanken bleiben im privaten Netz und werden via Bastion / VPN /
  Private Link erreicht.
- Komplette SQL-Statements mit gebundenen Werten auf INFO-Level
  loggen — gebundene Werte sind fast immer sensibel.

### BEKANNTE FALSCH-POSITIVE
- Reporting-Tools, die analystenautorisiertes Ad-hoc-SQL ausführen,
  interpolieren legitim Identifier; sie sollten gegen eine Read-Only-
  Replica mit einem separaten User laufen, dessen Grants Schaden
  verhindern.
- Einige ORMs (Django, SQLAlchemy 1.x) verwenden `%s`-Platzhalter als
  *Parameter-Marker*, nicht als Python-Format-String-Platzhalter — das
  ist sicher.
- Health-Check-Queries (`SELECT 1`) sind absichtlich trivial.

## Kontext (für Menschen)

SQL-Injection ist seit fünfzehn Jahren auf Platz 1 oder 2 jeder OWASP
Top 10 und bewegt sich nicht, weil der Failure-Mode *easy by default*
ist: jede Sprache mit String-Concat erlaubt dir, eine Query zu bauen.
KI-Assistenten generieren fröhlich "läuft-in-Dev"-Code, der User-Input
interpoliert — besonders für Sortier-Spalten, dynamische Filter und
Pagination.

Dieser Skill passt natürlich zu `api-security` (das die Route
schützt) und `secret-detection` (das den Connection-String schützt).

## Referenzen

- `rules/sql_injection_sinks.json`
- `rules/orm_safe_patterns.json`
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — SQL-Injection.
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
