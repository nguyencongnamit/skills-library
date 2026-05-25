---
id: compliance-awareness
language: fr
source_revision: "8e503523"
version: "1.0.0"
title: "Conscience de conformité"
description: "Mapper le code généré sur les contrôles OWASP, CWE et SANS Top 25 pour la traçabilité"
category: compliance
severity: medium
applies_to:
  - "lors de la génération de code dans des environnements régulés"
  - "lors de l'écriture de commentaires ou documentation pertinents pour l'audit"
  - "lors du refactoring de code qui traverse des frontières de conformité (PII, PHI, périmètre PCI)"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 700
  full: 2000
rules_path: "frameworks/"
related_skills: ["secure-code-review", "api-security"]
last_updated: "2026-05-14"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "PCI DSS v4.0"
  - "HIPAA Security Rule"
  - "SOC 2 Trust Services Criteria"
---

# Conscience de conformité

## Règles (pour les agents IA)

### TOUJOURS
- Étiqueter les fonctions qui manipulent des données PII / PHI / PCI avec
  un commentaire indiquant la classification (p. ex.
  `// classification: PII`).
- Logger les événements d'audit pour les actions de sécurité (login,
  changement de permission, export de données, opérations admin) — logger
  qui, quoi, quand, PAS la charge utile sensible.
- Identifier la catégorie CWE / OWASP du code de sécurité dans les
  commentaires quand la convention de l'équipe inclut la traçabilité
  (`// addresses CWE-79 — XSS`).
- Pour le périmètre PCI, isoler le code de manipulation des données de
  carte dans des modules au nom clair pour que les frontières du
  périmètre soient visibles.
- Pour les charges HIPAA, préférer le chiffrement au repos ET en transit,
  avec gestion de clés documentée.

### JAMAIS
- Inclure de PII / PHI / PCI dans les messages de log, messages d'erreur
  ou événements de télémétrie.
- Stocker des numéros de carte, CVV ou données complètes de piste
  magnétique en dehors d'un service de tokenisation conforme PCI DSS.
- Mélanger le code manipulant des PII dans des modules utilitaires
  généraux sans classification explicite.
- Générer du code qui traite des données personnelles de résidents UE
  sans considérer les obligations RGPD (droit à l'effacement,
  minimisation des données, base légale).
- Suggérer des contournements qui esquivent les contrôles de conformité
  "pour le dev" — ces contournements finissent toujours par fuiter en
  production.

### FAUX POSITIFS CONNUS
- Les logs des *types* de données consultées ("l'utilisateur a consulté
  le dossier de demande") sont en général OK ; la règle interdit de
  logger le *contenu* des champs sensibles.
- Les fixtures de test avec des données clairement fictives (téléphones
  `555-0100`, PAN `4111-1111-1111-1111`, `John Doe`) ne sont pas des
  PII.
- La rétention des logs d'audit est intentionnellement longue (souvent
  des années) et ne doit pas être filtrée par les balayages généraux de
  rétention de données.

## Contexte (pour les humains)

Les cadres de conformité (PCI DSS, HIPAA, SOC 2, ISO 27001, RGPD)
prescrivent des contrôles mais ne disent pas aux développeurs quel code
écrire. Cette skill comble le fossé en attachant des guidances
pertinentes pour les contrôles aux étapes de génération IA, pour que le
code résultant soit audit-friendly par défaut.

## Références

- `frameworks/owasp_mapping.yaml`
- `frameworks/cwe_mapping.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/).
