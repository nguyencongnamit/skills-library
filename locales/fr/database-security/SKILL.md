---
id: database-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité des bases de données"
description: "Prévenir l'injection SQL, le mauvais usage des ORM, les fuites de credentials ; imposer des utilisateurs DB en moindre privilège et des migrations sûres"
category: prevention
severity: critical
applies_to:
  - "lors de la génération de SQL ou de chaînes de requête raw"
  - "lors de la génération de code de modèles / requêtes ORM"
  - "lors de la génération de fichiers de migration de base de données"
  - "lors du câblage des chaînes de connexion ou du pooling"
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

# Sécurité des bases de données

## Règles (pour les agents IA)

### TOUJOURS
- Utiliser des requêtes paramétrées / prepared statements pour tout
  SQL qui touche à des valeurs contrôlées par l'utilisateur. Passer
  les valeurs en paramètres, jamais via concaténation ou formatage de
  chaînes (`%s`, `+`, template literals).
- Utiliser l'API de requête sûre de l'ORM. En SQLAlchemy :
  `session.execute(text(":id"), {"id": user_id})`. En Django :
  méthodes ORM, `Model.objects.filter(...)`. En Sequelize / Prisma /
  SQLAlchemy core : builders `.where({ ... })`. En Go :
  `db.QueryContext(ctx, "select ... where id = $1", id)`.
- Valider que les noms de colonnes / tables identifiants — qui ne
  peuvent pas être paramétrés — viennent d'une allowlist en dur, pas
  de l'input utilisateur.
- Utiliser un utilisateur de base de données dédié par application
  avec les grants minimaux nécessaires. Les apps web qui lisent
  seulement ne devraient pas avoir `INSERT`/`UPDATE`/`DELETE`. Les
  jobs de migration tournent comme un utilisateur séparé capable de
  `DDL`.
- Activer Row-Level Security (Postgres `CREATE POLICY` / Supabase
  RLS / Azure SQL RLS) pour les tables multi-tenant et fixer le
  contexte tenant par session.
- Tirer les credentials DB d'un secret manager ou d'une variable
  d'environnement injectée au démarrage — jamais d'un
  `database.yml` / `.env` versionné. Roter selon planning.
- Utiliser TLS vers la base de données (`sslmode=require` pour
  Postgres, `requireSSL=true` pour MySQL, connexion chiffrée pour
  MSSQL). Pinner la CA où le driver le supporte.
- Le pooling de connexions a une taille max qui rentre dans le
  `max_connections` de la DB, avec une back-pressure saine côté
  application.

### JAMAIS
- Concaténer l'input utilisateur dans du SQL : `"SELECT * FROM users
  WHERE name='" + name + "'"`. Même si vous l'"échappez" vous-même —
  les drivers échappent correctement seulement quand vous bindez via
  l'API de paramètres.
- Utiliser les méthodes raw de l'ORM (`.raw()`, `.objects.raw()`,
  `.query(text(...))`) avec interpolation f-string de l'input
  utilisateur.
- Faire tourner des workloads applicatifs en superuser de base de
  données / `root` / `postgres` / `sa`. Créer un utilisateur de
  service.
- Désactiver TLS vers la base (`sslmode=disable`, `useSSL=false`).
- Stocker des secrets, PII ou gros blobs dans des colonnes JSON sans
  chiffrement-au-repos et plan de rotation de clés.
- Lancer des migrations destructives (DROP TABLE, DROP COLUMN, ALTER
  COLUMN avec changement de type sur des tables peuplées) inline avec
  les déploiements sans plan d'expand–contract et backup vérifié
  restaurable.
- Binder un listener de base de données exposé à internet sans
  allowlist ; les bases de données restent dans un réseau privé et
  sont atteintes via bastion / VPN / private link.
- Logger les SQL complets avec les valeurs bindées au niveau INFO —
  les valeurs bindées sont presque toujours sensibles.

### FAUX POSITIFS CONNUS
- Les outils de reporting qui exécutent du SQL ad-hoc écrit par des
  analystes interpolent légitimement des identifiants ; ils
  devraient tourner contre une réplique read-only avec un
  utilisateur séparé dont les grants empêchent les dégâts.
- Certains ORMs (Django, SQLAlchemy 1.x) utilisent les placeholders
  `%s` comme *marqueurs de paramètres*, pas comme placeholders de
  format-string Python — c'est sûr.
- Les requêtes de health-check (`SELECT 1`) sont intentionnellement
  triviales.

## Contexte (pour les humains)

L'injection SQL est en position 1 ou 2 de chaque OWASP Top 10 depuis
quinze ans et ne bouge pas parce que le mode de défaillance est
*facile par défaut* : tout langage avec concaténation de chaînes vous
laisse produire une requête. Les assistants IA génèrent allègrement
du code "ça-marche-en-dev" qui interpole l'input utilisateur — en
particulier pour les colonnes de tri, filtres dynamiques et
pagination.

Cette skill s'associe naturellement avec `api-security` (qui garde la
route) et `secret-detection` (qui garde la chaîne de connexion).

## Références

- `rules/sql_injection_sinks.json`
- `rules/orm_safe_patterns.json`
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html).
- [CWE-89](https://cwe.mitre.org/data/definitions/89.html) — Injection SQL.
- [PostgreSQL Row-Level Security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html).
