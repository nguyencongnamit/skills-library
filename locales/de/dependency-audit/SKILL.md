---
id: dependency-audit
language: de
source_revision: "fbb3a823"
version: "1.0.0"
title: "Dependency-Audit"
description: "Projekt-Dependencies auf bekannte Vulnerabilities, malicious Packages und Supply-Chain-Risiken prüfen"
category: supply-chain
severity: high
applies_to:
  - "beim Hinzufügen einer neuen Dependency"
  - "beim Upgrade von Dependencies"
  - "beim Review von Package-Manifests (package.json, requirements.txt, go.mod, Cargo.toml)"
  - "vor dem Mergen eines PRs, der Dependency-Files ändert"
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

# Dependency-Audit

## Regeln (für KI-Agenten)

### IMMER
- Dependencies in Lockfiles auf exakte Versionen pinnen
  (`package-lock.json`, `yarn.lock`, `Pipfile.lock`, `poetry.lock`,
  `go.sum`, `Cargo.lock`).
- Jeden neuen Dependency-Namen gegen die mitgelieferte Malicious-
  Package-Liste in `vulnerabilities/supply-chain/malicious-packages/`
  abgleichen.
- Etablierte Pakete mit hohen Download-Zahlen, mehreren Maintainern und
  jüngster Aktivität gegenüber neueren Alternativen für dasselbe
  Problem bevorzugen.
- Das Audit-Kommando des Package Managers ausführen (`npm audit`,
  `pip-audit`, `cargo audit`, `govulncheck`) und gemeldete Issues vor
  dem Merge prüfen.
- Verifizieren, dass die auf der Package-Seite hinterlegte Repository-
  URL tatsächlich existiert und mit dem verlinkten GitHub- / GitLab- /
  Codeberg-Projekt übereinstimmt.

### NIE
- Eine Dependency hinzufügen, ohne die Version zu pinnen.
- Pakete mit `--unsafe-perm` oder vergleichbaren Flags installieren,
  die das Install-Sandboxing umgehen.
- Eine Dependency hinzufügen, deren Name in der mitgelieferten
  Malicious-Package-Liste auftaucht.
- Ein brandneues Paket (innerhalb der letzten 30 Tage veröffentlicht)
  ohne klare, dokumentierte Begründung hinzufügen — Typosquats sind
  meist frisch publiziert.
- Den `latest`-Tag in einem Produktiv-Lockfile oder in der FROM-Zeile
  eines Container-Images verwenden.
- Ungenutzte Dependencies committen — sie vergrößern die Angriffsfläche
  gratis.

### BEKANNTE FALSCH-POSITIVE
- Interne Monorepo-Pakete (`@yourco/*`), die als "unknown" gemeldet
  werden — sie sind gültig, wenn der Namespace deiner Organisation
  gehört.
- Neue Patch-Versionen stabiler Pakete (z. B. `react@18.2.5` nach
  `18.2.4`), die als "recently published" gemeldet werden — Patch-
  Updates sind meist unproblematisch.
- Paketnamen, die sich legitim mit jahrealten Malicious-Einträgen
  überschneiden, weil der ursprüngliche Maintainer den Namen neu
  registriert hat.

## Kontext (für Menschen)

Supply-Chain-Angriffe wachsen seit 2019 schneller als jede andere
Angriffskategorie. Die Kompromittierung eines beliebten Pakets
(event-stream, ua-parser-js, colors, faker, xz-utils) oder die
Veröffentlichung eines Typosquats (axois vs axios, urllib3 vs urlib3)
verschafft dem Angreifer zuverlässig innerhalb von Stunden Tausende
nachgelagerter Opfer.

KI-Coding-Tools sind besonders verwundbar, weil das Modell keinen
Einblick hat, wann ein Paket zuletzt kompromittiert wurde. Das Modell
empfiehlt, was es im Training gelernt hat; wurde ein Maintainer nach
dem Training-Cutoff kompromittiert, empfiehlt die KI fröhlich eine
Backdoor-Version.

Dieser Skill kompensiert das, indem er die Live-Malicious-Package-
Datenbank in den Arbeitskontext der KI einspeist und verlangt, dass
die KI sie konsultiert, bevor sie eine Dependency hinzufügt.

## Referenzen

- `rules/known_malicious.json` — Symlink oder Kopie der jeweils
  relevanten `vulnerabilities/supply-chain/malicious-packages/*.json`-
  Files.
- [OWASP Top 10 A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/).
- [npm Advisories](https://github.com/advisories?query=type%3Aunreviewed+ecosystem%3Anpm).
- [PyPI Advisory Database](https://github.com/pypa/advisory-database).
