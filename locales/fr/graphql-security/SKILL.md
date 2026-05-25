---
id: graphql-security
language: fr
source_revision: "4c215e6f"
version: "1.0.0"
title: "Sécurité de GraphQL"
description: "Défendre les API GraphQL : limites de profondeur/complexité, introspection en production, abus de batching/aliasing, autorisation au niveau du champ, persisted queries"
category: prevention
severity: high
applies_to:
  - "lors de la génération de schémas, resolvers ou configuration de serveur GraphQL"
  - "lors du câblage de l'authentification/autorisation à un endpoint GraphQL"
  - "lors de l'ajout d'une passerelle d'API GraphQL publique"
  - "lors de la revue de l'exposition de l'endpoint /graphql"
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

# Sécurité de GraphQL

## Règles (pour les agents IA)

### TOUJOURS
- Imposer une **profondeur maximale** de query (typique : 7–10) et
  une **complexité** (coût) de query côté serveur. Une query
  imbriquée sur 5 niveaux contre une relation many-to-many peut
  renvoyer des milliards de nœuds ; sans limite de coût, un seul
  client fait tomber la base de données.
- Désactiver l'**introspection** en production. L'introspection
  rend la reconnaissance triviale ; les clients légitimes ont le
  schéma intégré via codegen ou un artefact `.graphql`.
- Utiliser des **persisted queries** (hashes d'opérations en
  allowlist) pour toute API publique / à fort trafic. Du GraphQL
  anonyme arbitraire est l'équivalent GraphQL d'un
  `eval(req.body)`.
- Appliquer une **autorisation au niveau du champ** dans les
  resolvers, pas seulement à l'endpoint. GraphQL agrège plein de
  champs dans une seule réponse HTTP — un seul `@auth` manquant
  sur un champ sensible fait fuiter des données dans toute la
  query.
- Limiter le nombre d'**alias** par requête (typique : 15) et le
  nombre d'**opérations par batch** (typique : 5). Apollo / Relay
  permettent tous les deux des queries en batch — sans limites,
  c'est une primitive d'amplification de N pages de l'API.
- Rejeter tôt les définitions de **fragments circulaires** (la
  plupart des serveurs le font, mais pas les executors custom). Un
  fragment auto-référent provoque un coût de parsing exponentiel.
- Renvoyer des erreurs génériques aux clients
  (`INTERNAL_SERVER_ERROR`, `UNAUTHORIZED`) et router les stack
  traces / extraits SQL uniquement vers les logs serveur. Les
  erreurs par défaut d'Apollo font fuiter des internals du schéma
  et de la query.
- Définir une limite de taille de requête (typique : 100 Kio) et
  un timeout de requête (typique : 10 s) sur la couche HTTP devant
  le serveur GraphQL. Une query GraphQL de 1 Mio n'a aucun usage
  légitime.

### JAMAIS
- Exposer l'introspection de `/graphql` sur un endpoint de
  production. Le playground GraphQL (GraphiQL, Apollo Sandbox)
  doit aussi être désactivé dans les builds de production.
- Faire confiance à la profondeur / complexité d'une query parce
  que "nos clients n'envoient que des queries bien formées".
  N'importe quel attaquant peut forger à la main une requête vers
  `/graphql`.
- Laisser des directives `@skip(if: ...)` / `@include(if: ...)`
  piloter les vérifications d'autorisation. Les directives
  s'exécutent après l'autorisation dans la plupart des executors,
  mais des ordres custom de directives ont produit des bypasses
  d'authz.
- Implémenter des patterns N+1 dans les resolvers (une requête DB
  par enregistrement parent). Utiliser un DataLoader ou un fetch
  basé sur des jointures. N+1 est à la fois un bug de performance
  et un amplificateur de DoS.
- Autoriser les uploads de fichiers via GraphQL multipart
  (`apollo-upload-server`, `graphql-upload`) sans limites de
  taille, validation MIME et scan antivirus hors-bande. Le
  CVE-2020-7754 de 2020 (`graphql-upload`) a montré comment un
  multipart malformé peut faire crasher le serveur.
- Cacher les réponses GraphQL uniquement par URL. POST `/graphql`
  utilise toujours la même URL ; le cache doit clé par hash
  d'opération + variables + claims d'auth pour éviter les fuites
  inter-tenants.
- Exposer des mutations qui prennent des objets `input:` en JSON
  non fiable sans validation de schéma. Les types GraphQL sont
  obligatoires au niveau du schéma, mais les types `JSON` /
  `Scalar` les contournent entièrement.

### FAUX POSITIFS CONNUS
- Les endpoints GraphQL internes d'admin derrière un VPN
  authentifié peuvent légitimement laisser l'introspection
  activée pour le confort des développeurs.
- Les persisted queries en allowlist statique rendent les
  vérifications de profondeur / complexité redondantes sur ces
  opérations — conserver les vérifications pour toute opération
  hors allowlist (c.-à-d. via un flag `disabled`).
- Les API de données publiques en lecture seule peuvent utiliser
  des limites de coût très hautes avec un caching agressivement
  configuré au niveau CDN ; le compromis est documenté par
  endpoint.

## Contexte (pour les humains)

GraphQL donne aux clients un langage de requête. Ce langage est
Turing-complet en pratique — profondeur, aliasing, fragments et
unions se combinent pour former une computation quasi arbitraire
contre le graphe de resolvers. Traiter `/graphql` comme un
endpoint unique avec de simples contrôles WAF / rate-limit est
insuffisant.

L'ère 2022-2024 des incidents GraphQL (Hyatt, recherche Slack
issue d'Apollo, plusieurs cas d'account-takeover via batching) ont
toutes tenu soit à une autorisation au niveau du champ manquante,
soit à une analyse de coût manquante. graphql-armor (Escape) et
les règles de validation incluses dans Apollo fournissent
désormais un middleware prêt à l'emploi pour la plupart d'entre
elles — utilisez-les.

## Références

- `rules/graphql_safe_config.json`
- [OWASP GraphQL Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html).
- [CWE-400](https://cwe.mitre.org/data/definitions/400.html).
- [Apollo Production Checklist](https://www.apollographql.com/docs/apollo-server/security/production-checklist/).
- [graphql-armor](https://escape.tech/graphql-armor/).
