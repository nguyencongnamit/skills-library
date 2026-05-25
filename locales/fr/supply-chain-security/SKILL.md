---
id: supply-chain-security
language: fr
source_revision: "fbb3a823a2a0"
version: "1.0.0"
title: "Sécurité de la chaîne d'approvisionnement"
description: "Détecter paquets malveillants, typosquats, confusion de dépendances et compromissions de registre"
category: prevention
severity: critical
applies_to:
  - "lors de l'ajout d'une nouvelle dépendance"
  - "lors de la mise à jour des fichiers de verrouillage"
  - "lors de l'ajout de registres privés ou d'organisation"
languages: ["*"]
token_budget:
  minimal: 900
  compact: 1300
  full: 2200
rules_path: "rules/"
related_skills: ["dependency-audit", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Top 10 — A06 : Composants vulnérables et obsolètes"
  - "MITRE ATT&CK T1195.002 — Compromission de chaîne logicielle"
  - "NIST SP 800-161r1"
---

# Sécurité de la chaîne d'approvisionnement

## Règles (pour agents IA)

### TOUJOURS
- Vérifier le nom du paquet par rapport à la base de typosquats avant
  installation. Erreurs fréquentes : `reqests`/`request` pour `requests`,
  `colourama` pour `colorama`, `lodahs` pour `lodash`.
- Verrouiller les versions via un lockfile (`package-lock.json`,
  `poetry.lock`, `Cargo.lock`, `go.sum`). Activer la vérification
  d'intégrité (`npm ci`, `pip install --require-hashes`).
- Croiser avec la base d'incidents documentés (xz-utils CVE-2024-3094,
  `coa`, `eslint-scope`, `ultralytics`, `polyfill.io`,
  `pytorch-nightly`).
- Désactiver les scripts d'installation lorsque c'est possible
  (`--ignore-scripts`).

### JAMAIS
- Installer un paquet « parce que son nom semble bon » sans vérification.
- Permettre qu'un paquet privé porte le même nom qu'un paquet public
  (confusion de dépendances).
- Faire confiance à une URL `curl | bash` sans épingler son SHA-256.
- Accepter les mises à jour publiées par un mainteneur dans les
  dernières 72 heures sans audit.

### FAUX POSITIFS CONNUS
- Paquets officiels à nom court (`fs`, `os`, `re`).
- Forks légitimes préfixés `@org/`.

## Contexte

La chaîne d'approvisionnement logicielle est l'un des vecteurs d'attaque
à plus forte amplification : compromettre un mainteneur peut toucher
des milliers de consommateurs. Maintenez un SBOM, exigez la signature
et inspectez tout changement de propriété ou toute publication
inhabituelle.

## Références

- OWASP A06:2021
- MITRE ATT&CK T1195.002
- NIST SP 800-161r1
- SLSA — Supply-chain Levels for Software Artifacts
