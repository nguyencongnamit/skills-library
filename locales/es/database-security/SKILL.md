---
id: database-security
language: es
source_revision: "afe376a8"
version: "1.0.0"
title: "Seguridad de bases de datos"
description: "Prevenir inyección SQL, mal uso de ORM, fugas de credenciales; exigir usuarios DB con privilegios mínimos y migraciones seguras"
category: prevention
severity: critical
applies_to:
  - "al generar SQL o cadenas de query raw"
  - "al generar código de modelos / queries ORM"
  - "al generar archivos de migración de base de datos"
  - "al cablear cadenas de conexión o pooling"
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

# Seguridad de bases de datos

## Reglas (para agentes de IA)

### SIEMPRE
- Usar queries parametrizadas / prepared statements para cualquier SQL
  que toque valores controlados por el usuario. Pasar valores como
  parámetros, nunca vía concatenación o formato de strings (`%s`, `+`,
  template literals).
- Usar la API segura de queries del ORM. En SQLAlchemy:
  `session.execute(text(":id"), {"id": user_id})`. En Django: métodos
  ORM, `Model.objects.filter(...)`. En Sequelize / Prisma / SQLAlchemy
  core: builders `.where({ ... })`. En Go:
  `db.QueryContext(ctx, "select ... where id = $1", id)`.
- Validar que nombres de columnas / tablas identificadores — que no se
  pueden parametrizar — vengan de una allowlist hardcodeada, no de
  input de usuario.
- Usar un usuario de base de datos dedicado por aplicación con los
  grants mínimos necesarios. Las apps web que solo leen no deberían
  tener `INSERT`/`UPDATE`/`DELETE`. Los jobs de migración corren como
  un usuario separado con capacidad `DDL`.
- Habilitar Row-Level Security (Postgres `CREATE POLICY` / Supabase
  RLS / Azure SQL RLS) para tablas multi-tenant y fijar el contexto
  de tenant por sesión.
- Sacar credenciales de DB de un secret manager o variable de entorno
  inyectada al arrancar — nunca de un `database.yml` / `.env`
  versionado. Rotar según calendario.
- Usar TLS hacia la base de datos (`sslmode=require` para Postgres,
  `requireSSL=true` para MySQL, conexión cifrada para MSSQL). Pinear
  la CA donde el driver lo soporte.
- El pooling de conexiones tiene un tamaño máximo que cabe dentro del
  `max_connections` de la DB, con back-pressure sano hacia la app.

### NUNCA
- Concatenar input de usuario en SQL:
  `"SELECT * FROM users WHERE name='" + name + "'"`. Aunque lo
  "escapes" a mano — los drivers escapan correctamente solo cuando
  bindeás por la API de parámetros.
- Usar métodos raw del ORM (`.raw()`, `.objects.raw()`,
  `.query(text(...))`) con interpolación f-string de input de
  usuario.
- Correr cargas de trabajo de la aplicación como el superusuario de
  base de datos / `root` / `postgres` / `sa`. Crear un usuario de
  servicio.
- Deshabilitar TLS hacia la base de datos (`sslmode=disable`,
  `useSSL=false`).
- Guardar secretos, PII o blobs grandes en columnas JSON sin
  encriptación-en-reposo y plan de rotación de claves.
- Correr migraciones destructivas (DROP TABLE, DROP COLUMN, ALTER
  COLUMN cambiando tipo en tablas pobladas) inline con deploys sin un
  plan de expand-contract y un backup verificado-restaurable.
- Bindear un listener de base de datos expuesto a internet sin
  allowlist; las bases de datos se quedan en red privada y se acceden
  vía bastión / VPN / private link.
- Loguear sentencias SQL enteras con valores bindeados a nivel INFO —
  los valores bindeados son casi siempre sensibles.

### FALSOS POSITIVOS CONOCIDOS
- Las herramientas de reporting que corren SQL ad-hoc autoría-analista
  legítimamente interpolan identificadores; deberían correr contra
  una réplica read-only con un usuario separado cuyos grants impidan
  daño.
- Algunos ORM (Django, SQLAlchemy 1.x) usan placeholders `%s` como
  *marcadores de parámetro*, no placeholders de format-string de
  Python — eso es seguro.
- Queries de health-check (`SELECT 1`) son trivialmente intencionadas.

## Contexto (para humanos)

La inyección SQL ha estado #1 o #2 en cada OWASP Top 10 durante
quince años y no se mueve porque el modo de falla es *fácil por
defecto*: cualquier lenguaje con concatenación de strings te deja
producir una query. Los asistentes de IA generan felizmente código
"funciona-en-dev" que interpola input de usuario — particularmente
para columnas de ordenamiento, filtros dinámicos y paginación.

Esta skill empareja naturalmente con `api-security` (que guarda la
ruta) y `secret-detection` (que guarda la cadena de conexión).

## Referencias

- `rules/sql_injection_sinks.json`
- `rules/orm_safe_patterns.json`
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Inyección SQL.
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
