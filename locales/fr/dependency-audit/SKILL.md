---
id: dependency-audit
language: fr
source_revision: "fbb3a823"
version: "1.0.0"
title: "Audit des dépendances"
description: "Auditer les dépendances du projet pour vulnérabilités connues, paquets malveillants et risques supply-chain"
category: supply-chain
severity: high
applies_to:
  - "lors de l'ajout d'une nouvelle dépendance"
  - "lors de la mise à jour des dépendances"
  - "lors de la revue des manifests de paquets (package.json, requirements.txt, go.mod, Cargo.toml)"
  - "avant de merger une PR qui modifie des fichiers de dépendances"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 750
  full: 1900
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security"]
last_updated: "2026-05-12"
sources:
  - "OWASP Top 10 2021 — A06: Vulnerable and Outdated Components"
  - "CWE-1104: Use of Unmaintained Third Party Components"
  - "CISA Software Bill of Materials guidance"
---

# Audit des dépendances

## Règles (pour les agents IA)

### TOUJOURS
- Pinner les dépendances à des versions exactes dans les lockfiles
  (`package-lock.json`, `yarn.lock`, `Pipfile.lock`, `poetry.lock`,
  `go.sum`, `Cargo.lock`).
- Croiser le nom de chaque nouvelle dépendance avec la liste des
  paquets malveillants embarquée dans
  `vulnerabilities/supply-chain/malicious-packages/`.
- Préférer des paquets bien établis avec un nombre élevé de
  téléchargements, plusieurs mainteneurs et une activité récente
  plutôt que des alternatives plus récentes résolvant le même
  problème.
- Lancer la commande audit du package manager (`npm audit`,
  `pip-audit`, `cargo audit`, `govulncheck`) et examiner les
  problèmes signalés avant de merger.
- Vérifier que l'URL du repository indiquée sur la page du paquet
  existe réellement et correspond au projet GitHub / GitLab /
  Codeberg lié.

### JAMAIS
- Ajouter une dépendance sans pinner sa version.
- Installer des paquets avec `--unsafe-perm` ou des flags équivalents
  qui contournent le sandboxing à l'installation.
- Ajouter une dépendance dont le nom apparaît dans la liste de paquets
  malveillants embarquée.
- Ajouter un paquet flambant neuf (publié dans les 30 derniers jours)
  sans raison claire et documentée — les typosquats sont
  généralement fraîchement publiés.
- Utiliser le tag `latest` dans un lockfile de production ou dans la
  ligne FROM d'une image de container.
- Committer des dépendances inutilisées — elles étendent la surface
  d'attaque gratuitement.

### FAUX POSITIFS CONNUS
- Les paquets internes du monorepo (`@yourco/*`) marqués "unknown" —
  ils sont valides quand le namespace appartient à votre organisation.
- Les nouvelles versions de patch de paquets stables (p. ex.
  `react@18.2.5` après `18.2.4`) marquées "récemment publiées" — les
  updates de patch sont généralement OK.
- Les noms de paquets qui se chevauchent légitimement avec des entrées
  malveillantes anciennes que le mainteneur d'origine a réenregistrées.

## Contexte (pour les humains)

Les attaques supply-chain croissent plus vite que toute autre
catégorie d'attaque depuis 2019. Compromettre un paquet populaire
(event-stream, ua-parser-js, colors, faker, xz-utils) ou publier un
typosquat (axois vs axios, urllib3 vs urlib3) rapporte
systématiquement à l'attaquant des milliers de victimes en aval en
quelques heures.

Les outils de coding IA sont particulièrement vulnérables parce que
le modèle n'a aucune visibilité sur la dernière compromission d'un
paquet. Le modèle recommande ce qu'il a appris pendant l'entraînement ;
si un mainteneur a été compromis après le cutoff d'entraînement, l'IA
recommande joyeusement une version avec backdoor.

Cette skill compense en injectant la base de données vivante des
paquets malveillants dans le contexte de travail de l'IA et en
exigeant que l'IA la consulte avant d'ajouter toute dépendance.

## Références

- `rules/known_malicious.json` — symlink ou copie des fichiers
  pertinents `vulnerabilities/supply-chain/malicious-packages/*.json`.
- [OWASP Top 10 A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/).
- [npm Advisories](https://github.com/advisories?query=type%3Aunreviewed+ecosystem%3Anpm).
- [PyPI Advisory Database](https://github.com/pypa/advisory-database).
