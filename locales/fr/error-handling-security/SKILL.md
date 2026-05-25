---
id: error-handling-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité du traitement des erreurs"
description: "Pas de stack traces / SQL / chemins / versions de framework dans les réponses client ; erreurs génériques en sortie, erreurs structurées dans les logs"
category: prevention
severity: medium
applies_to:
  - "lors de la génération de handlers d'erreur HTTP / GraphQL / RPC"
  - "lors de la génération de blocs exception / panic / rescue"
  - "lors du câblage des pages d'erreur par défaut du framework"
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

# Sécurité du traitement des erreurs

## Règles (pour les agents IA)

### TOUJOURS
- Attraper les exceptions à la frontière (handler HTTP, méthode RPC,
  consumer de messages). Les logger avec contexte complet côté
  serveur ; renvoyer une erreur assainie vers l'extérieur.
- Les réponses d'erreur externes incluent : un code d'erreur stable,
  un message court lisible humainement et un ID de corrélation /
  requête. Elles n'incluent jamais : stack trace, fragment SQL,
  chemin de fichier, hostname interne, bannière de version du
  framework.
- Logger les erreurs au bon niveau : `ERROR` / `WARN` pour les
  défaillances actionnables ; `INFO` pour les résultats métier
  attendus ; `DEBUG` pour le détail de diagnostic (et seulement si
  explicitement activé).
- Renvoyer des réponses d'erreur uniformes sur toute la surface de
  l'API — même forme, même jeu de codes — pour que les attaquants
  ne puissent pas inférer un comportement à partir des variations
  d'erreur (p. ex. login : même message et même timing pour
  "mauvais username" vs "mauvais password").
- Désactiver les pages d'erreur par défaut du framework en production
  (`app.debug = False` / `Rails.env.production?` /
  `Environment=Production` / `DEBUG=False`). Les remplacer par une
  page 5xx ne renvoyant que l'ID de corrélation.
- Utiliser un helper centralisé de rendu d'erreur pour que les
  règles d'assainissement vivent au même endroit, sans duplication.

### JAMAIS
- Rendre `traceback.format_exc()`, `e.toString()`,
  `printStackTrace()`, `panic` ou les pages de debug du framework au
  client en production.
- Refléter les requêtes / paramètres SQL dans les messages d'erreur
  — `IntegrityError: duplicate key value violates unique constraint
  "users_email_key"` indique à l'attaquant le nom de la table et de
  la colonne.
- Fuiter l'information de présence d'enregistrement : `User not
  found` vs `Invalid password` permet d'énumérer les comptes.
  Utiliser un message unique pour les deux.
- Fuiter des chemins de filesystem
  (`/var/www/app/src/handlers.py`) ou des bannières de version
  (`X-Powered-By: Express/4.17.1`).
- Traiter `try / except: pass` comme du traitement d'erreur ; soit
  l'exception est attendue (logger + continuer), soit elle ne l'est
  pas (la laisser se propager).
- Utiliser des réponses d'erreur 4xx pour valider la forme de
  l'input — les bots itèrent sur les paramètres et utilisent le body
  de la réponse pour apprendre le schéma. Renvoyer un 400 uniforme
  plus un ID de corrélation pour l'input malformé.
- Envoyer les détails complets d'erreur (y compris PII) à un service
  tiers d'error tracking sans scrubber. Redacter `password`,
  `Authorization`, `Cookie`, `Set-Cookie`, `token`, `secret` et les
  patterns PII courants.

### FAUX POSITIFS CONNUS
- Les pages d'erreur pour développeurs sur `localhost` / `*.local`
  sont ok.
- Une poignée d'endpoints API (debug, admin, RPC interne) peuvent
  légitimement renvoyer plus de détail ; ils doivent exiger des
  appelants authentifiés et autorisés et ne jamais être
  atteignables depuis internet.
- Les health checks et smoke tests CI exposent du détail
  intentionnellement quand ils sont invoqués depuis l'intérieur du
  cluster.

## Contexte (pour les humains)

CWE-209 est un texte court à fort impact : c'est ainsi que les
attaquants passent de "ce service existe" à "ce service tourne
Spring 5.2 sur Tomcat 9 avec une table PostgreSQL nommée `users` et
une colonne nommée `email_normalized`". Chaque détail
supplémentaire dans le message d'erreur réduit le coût de l'attaque
suivante.

Cette skill est volontairement étroite et se couple avec
`logging-security` (le côté *log* de la même opération) et
`api-security` (la forme de la réponse).

## Références

- `rules/error_response_template.json`
- `rules/redaction_patterns.json`
- [OWASP Error Handling Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html).
- [CWE-209](https://cwe.mitre.org/data/definitions/209.html).
