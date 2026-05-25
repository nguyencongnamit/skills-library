---
id: api-security
language: fr
source_revision: "fbb3a823"
version: "1.0.0"
title: "Sécurité des API"
description: "Appliquer les patterns OWASP API Top 10 à l'authentification, l'autorisation et la validation des entrées"
category: prevention
severity: high
applies_to:
  - "lors de la génération de handlers HTTP"
  - "lors de la génération de resolvers GraphQL"
  - "lors de la génération de méthodes de service gRPC"
  - "lors de la revue de changements sur les endpoints d'API"
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

# Sécurité des API

## Règles (pour les agents IA)

### TOUJOURS
- Exiger l'authentification sur chaque endpoint non public. Par défaut,
  authentifié ; les routes véritablement publiques sont marquées explicitement.
- Appliquer l'autorisation au niveau de l'objet — confirmer que le sujet
  authentifié a effectivement accès à l'ID de ressource demandé, pas seulement
  qu'il est connecté (cela neutralise la classe OWASP API1 BOLA / IDOR).
- Valider toutes les entrées de la requête contre un schéma explicite (JSON
  Schema, Pydantic, Zod, struct tags validator/v10). Rejeter tôt ; ne jamais
  propager d'entrée non fiable en profondeur.
- Appliquer des limites de débit au niveau de la route pour les endpoints
  d'authentification, de réinitialisation de mot de passe et toute opération
  coûteuse.
- Utiliser des access tokens à courte durée de vie (≤ 1 heure) avec des refresh
  tokens, pas des bearer tokens à longue durée.
- Renvoyer des messages d'erreur génériques à l'extérieur (`invalid
  credentials`) et journaliser les détails en interne — éviter de divulguer
  lequel de l'identifiant ou du mot de passe était incorrect.
- Inclure `Cache-Control: no-store` sur les réponses contenant des données
  personnelles ou sensibles.

### JAMAIS
- Utiliser des IDs entiers séquentiels dans les URLs pour des ressources
  accessibles entre locataires. Utiliser des UUIDs ou des IDs opaques
  imprévisibles.
- Faire confiance aux en-têtes `Authorization` sans vérifier la signature et
  l'expiration.
- Accepter des JWT avec l'algorithme `none`. Épingler l'algorithme attendu au
  moment de la vérification.
- Faire du mass-assignment du corps de requête directement vers des modèles ORM
  (`User(**request.json)`) — cela permet une escalade de privilèges quand le
  modèle a des champs admin que l'utilisateur ne devrait pas contrôler.
- Désactiver la protection CSRF sur les endpoints modificateurs d'état utilisés
  par les navigateurs.
- Renvoyer des stack traces ou des pages d'erreur du framework au client en
  production.
- Utiliser `HTTP GET` pour toute opération modificatrice d'état — GET doit être
  sûr et idempotent.

### FAUX POSITIFS CONNUS
- Les endpoints de site marketing publics qui servent du trafic anonyme n'ont
  légitimement pas d'authentification ni de limite de débit au-delà du load
  balancer.
- Les IDs séquentiels dans les chemins sont acceptables pour des ressources
  véritablement publiques et non rattachées à un locataire (p. ex. slugs de
  posts de blog, catalogue produit public).
- Les endpoints de health check (`/healthz`, `/ready`) contournent
  intentionnellement l'authentification.

## Contexte (pour les humains)

Le OWASP API Top 10 diffère du Top 10 web surtout parce que les APIs ont des
valeurs par défaut plus faibles : elles omettent souvent CSRF, exposent
directement les IDs d'objets, et tendent à faire confiance à l'état côté client
fourni par le développeur. Cette skill codifie les erreurs à fort impact les
plus courantes.

## Références

- `checklists/auth_patterns.yaml`
- `checklists/input_validation.yaml`
- [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x00-introduction/).
- [RFC 9700 — OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/rfc9700).
