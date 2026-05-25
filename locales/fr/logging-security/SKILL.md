---
id: logging-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité du logging"
description: "Prévenir les fuites de secrets/PII dans les logs, les attaques de log-injection, l'absence d'audit trail et la rétention faible"
category: prevention
severity: high
applies_to:
  - "lors de la génération d'appels logger ou de schémas de logging structuré"
  - "lors du câblage de log shippers, sinks, rétention et contrôles d'accès"
  - "lors de la revue des exigences d'audit logging"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["secret-detection", "error-handling-security", "compliance-awareness"]
last_updated: "2026-05-13"
sources:
  - "OWASP Logging Cheat Sheet"
  - "CWE-532 — Insertion of Sensitive Information into Log File"
  - "CWE-117 — Improper Output Neutralization for Logs"
  - "NIST SP 800-92 (Guide to Computer Security Log Management)"
---

# Sécurité du logging

## Règles (pour les agents IA)

### TOUJOURS
- Logger dans un **format structuré** (JSON ou logfmt) avec des
  noms de champ stables. Inclure `timestamp`, `service`, `version`,
  `level`, `trace_id`, `span_id`, `user_id` (quand authentifié),
  `request_id`, `event`.
- Faire passer chaque message de log par un **redactor** avant
  qu'il n'arrive au sink : mots de passe, tokens, clés d'API,
  cookies, URLs complètes contenant `?token=`, motifs PII courants
  (style SSN, style numéro de carte, e-mail en option).
- Sanitiser les newlines / caractères de contrôle dans toute
  chaîne contrôlée par l'utilisateur avant de la logger (CWE-117) :
  remplacer `\n`, `\r`, `\t` pour qu'un attaquant ne puisse pas
  injecter de fausses lignes de log.
- Logger les événements pertinents pour la sécurité en tant que
  **enregistrements d'audit immuables** : succès/échec de login,
  challenges MFA, changement de mot de passe, changement de rôle,
  octroi/révocation d'accès, export de données, action d'admin.
  Les enregistrements d'audit ont une rétention plus longue et un
  accès plus strict.
- Définir la rétention par catégorie de données, pas globalement :
  courte pour debug, longue pour audit, pas de PII après
  expiration du consentement.
- Expédier les logs vers un store centralisé et append-only (Cloud
  Logging, CloudWatch, Elastic, Loki) avec un accès en lecture
  restreint à engineering / SecOps.
- Alerter sur l'absence de logs d'un service (silent failure) et
  sur les anomalies de volume (pic 10× ou chute 10×).

### JAMAIS
- Logger des bodies de requête / réponse complets en INFO. Les
  bodies contiennent régulièrement mots de passe, tokens, PII et
  fichiers uploadés.
- Logger les headers `Authorization`, les headers `Cookie` /
  `Set-Cookie`, les tokens en query-string, ni aucun champ nommé
  `password`, `secret`, `token`, `key`, `private` ou `credential`
  — même après une "obfuscation" en `***`.
- Logger les statements SQL entièrement bindés avec leurs valeurs
  de paramètre ; logger plutôt le template + les *noms* des
  paramètres + un identifiant hashé de la valeur.
- Autoriser des utilisateurs non-privilégiés à lire les logs bruts
  contenant les données d'autres utilisateurs.
- Utiliser un `print()` / `console.log` / `fmt.Println` brut en
  service de production ; utiliser le logger configuré pour que
  rédaction et structure s'appliquent uniformément.
- Désactiver le logging des tentatives d'authentification ratées
  pour "réduire le bruit" — la détection brute-force dépend de
  ces enregistrements.
- Logger vers un fichier unique sur disque local en production ;
  ces logs sont perdus quand le pod / container / la VM meurt.

### FAUX POSITIFS CONNUS
- Les logs de health-check ou de probe du load balancer peuvent
  légitimement être sous-échantillonnés / supprimés au load
  balancer pour économiser du volume.
- Une valeur de `request_id` qui ressemble à un token n'est pas un
  token — les redactors qui matchent par motif peuvent
  sur-rédiger ; whitelister les préfixes sûrs connus (p. ex. tes
  IDs de corrélation `req_`).
- Les logs d'accès aux APIs publiques anonymes sans header
  d'auth ne sont pas un problème de privacy en soi ; les IPs
  client peuvent rester du PII sous RGPD.

## Contexte (pour les humains)

Les logs sont l'endroit le plus fréquent où les secrets finissent
en texte clair — dumps de requêtes, traces d'exception, prints de
debug, télémétrie de SDKs tiers. L'OWASP Logging Cheat Sheet
couvre les règles opérationnelles ; NIST SP 800-92 couvre la
rétention / centralisation / audit trail. Les exigences d'audit
trail apparaissent dans SOC 2 CC7.2, PCI-DSS 10, HIPAA
§164.312(b) et ISO 27001 A.12.4.

Ce skill est le partenaire de `secret-detection` (qui scanne le
source) et `error-handling-security` (qui sanitise la réponse
externe). Les logs se trouvent entre les deux et saignent dans
les deux directions.

## Références

- `rules/redaction_patterns.json`
- `rules/audit_event_schema.json`
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final).
