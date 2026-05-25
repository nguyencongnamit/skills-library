---
id: secure-code-review
language: fr
source_revision: "fbb3a823"
version: "1.0.0"
title: "Revue de code sécurisée"
description: "Appliquer les patterns OWASP Top 10 et CWE Top 25 pendant la génération et la revue de code"
category: prevention
severity: high
applies_to:
  - "lors de la génération de nouveau code"
  - "lors de la revue de pull requests"
  - "lors du refactoring de chemins sensibles à la sécurité (auth, gestion d'input, I/O de fichiers)"
  - "lors de l'ajout de nouveaux handlers ou endpoints HTTP"
languages: ["*"]
token_budget:
  minimal: 700
  compact: 900
  full: 2400
rules_path: "checklists/"
related_skills: ["api-security", "secret-detection", "infrastructure-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "SEI CERT Coding Standards"
---

# Revue de code sécurisée

## Règles (pour les agents IA)

### TOUJOURS
- Utiliser des queries paramétrées / prepared statements pour tout accès
  base de données. Ne jamais construire du SQL par concaténation de
  strings, même pour des inputs "de confiance".
- Valider l'input à la trust boundary — type, longueur, caractères
  autorisés, plage autorisée — et rejeter avant traitement.
- Encoder l'output pour le contexte de rendu (HTML escape pour HTML,
  URL encode pour query params, JSON encode pour output JSON).
- Utiliser la librairie de cryptographie built-in du langage, jamais de
  crypto fait main. Préférer AES-GCM pour le chiffrement symétrique,
  Ed25519 / RSA-PSS pour les signatures, Argon2id / bcrypt pour le
  hashing de password.
- Utiliser `crypto/rand` (Go), le module `secrets` (Python),
  `crypto.randomBytes` (Node.js), ou le CSPRNG de la plateforme pour
  toute valeur aléatoire impliquée dans la sécurité (tokens, IDs, session
  keys).
- Mettre des headers de sécurité explicites sur les responses HTTP :
  `Content-Security-Policy`, `Strict-Transport-Security`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`.
- Utiliser le principe du moindre privilège pour les paths de fichiers,
  les utilisateurs de base de données, les policies IAM et les privilèges
  de process.

### JAMAIS
- Construire des queries SQL/NoSQL par concaténation de strings avec de
  l'input utilisateur.
- Passer de l'input utilisateur directement à `exec`, `system`, `eval`,
  `Function()`, `child_process`, `subprocess.run(shell=True)`, ou tout
  autre path d'exécution de commande.
- Faire confiance à la validation côté client. Toujours re-valider côté
  serveur.
- Utiliser `MD5` ou `SHA1` pour aucun nouveau but sensible à la sécurité
  (passwords, signatures, HMAC). Utiliser SHA-256 / SHA-3 / BLAKE2 /
  Argon2id à la place.
- Utiliser le mode ECB pour aucun chiffrement, jamais. Préférer GCM, CCM
  ou ChaCha20-Poly1305.
- Utiliser `==` pour comparer des passwords — utiliser une comparaison à
  temps constant (`hmac.compare_digest`, `crypto.timingSafeEqual`,
  `subtle.ConstantTimeCompare`).
- Laisser l'input utilisateur déterminer des paths de fichier sans
  canonicalisation et checks de allowlist (défend contre le path
  traversal style `../../../etc/passwd`).
- Désactiver la vérification de certificat TLS en code de production —
  `verify=False`, `InsecureSkipVerify: true`,
  `rejectUnauthorized: false`.

### FAUX POSITIFS CONNUS
- Les outils admin internes qui exécutent intentionnellement des commandes
  shell contre des arguments fixes et de confiance sont acceptables
  quand ils sont documentés et code-reviewed.
- Les vecteurs de test cryptographiques utilisant `MD5` / `SHA1` pour la
  compatibilité avec des protocoles documentés (ex. tests d'interop
  legacy) sont acceptables.
- La comparaison à temps constant est overkill pour des comparaisons non
  secrètes (égalité de string dans des logs, matching de tags).

## Contexte (pour les humains)

La plupart des vulnérabilités web modernes se ramènent à la même poignée
de causes racines : ne pas valider l'input, ne pas utiliser la primitive
cryptographique correcte, ne pas appliquer le moindre privilège, ne pas
utiliser les défenses built-in du framework. Ce skill est la checklist
de l'IA pour ne pas tomber dans ces pièges.

## Références

- `checklists/owasp_top10.yaml`
- `checklists/injection_patterns.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
