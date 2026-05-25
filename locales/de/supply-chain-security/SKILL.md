---
id: supply-chain-security
language: de
source_revision: "fbb3a823a2a0"
version: "1.0.0"
title: "Lieferkettensicherheit"
description: "Bösartige Pakete, Typosquats, Dependency-Confusion und Registry-Kompromittierungen erkennen"
category: prevention
severity: critical
applies_to:
  - "beim Hinzufügen neuer Abhängigkeiten"
  - "beim Aktualisieren von Lockfiles"
  - "beim Einbinden privater oder organisationsinterner Registries"
languages: ["*"]
token_budget:
  minimal: 900
  compact: 1300
  full: 2200
rules_path: "rules/"
related_skills: ["dependency-audit", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Top 10 — A06: Anfällige und veraltete Komponenten"
  - "MITRE ATT&CK T1195.002 — Supply Chain Compromise"
  - "NIST SP 800-161r1"
---

# Lieferkettensicherheit

## Regeln (für KI-Agenten)

### IMMER
- Paketnamen vor der Installation gegen die Typosquat-Datenbank
  prüfen. Häufige Fehler: `reqests`/`request` statt `requests`,
  `colourama` statt `colorama`, `lodahs` statt `lodash`.
- Versionen über ein Lockfile fixieren (`package-lock.json`,
  `poetry.lock`, `Cargo.lock`, `go.sum`) und Integritätsprüfung
  aktivieren (`npm ci`, `pip install --require-hashes`).
- Gegen dokumentierte Vorfälle abgleichen (xz-utils CVE-2024-3094,
  `coa`, `eslint-scope`, `ultralytics`, `polyfill.io`,
  `pytorch-nightly`).
- Installations-Skripte deaktivieren, wenn möglich (`--ignore-scripts`).

### NIEMALS
- Ein Paket installieren, „weil der Name passend aussieht", ohne
  Prüfung.
- Zulassen, dass ein privates Paket denselben Namen wie ein öffentliches
  trägt (Dependency Confusion).
- `curl | bash` ohne SHA-256-Pinning vertrauen.
- Updates akzeptieren, die ein Maintainer innerhalb der letzten 72
  Stunden veröffentlicht hat, ohne Audit.

### BEKANNTE FALSCH-POSITIVE
- Offizielle Pakete mit sehr kurzen Namen (`fs`, `os`, `re`).
- Legitime Forks mit Präfix `@org/`.

## Kontext

Die Software-Lieferkette ist einer der wirkungsstärksten Angriffsvektoren:
ein kompromittierter Maintainer kann Tausende von Konsumenten treffen.
Halten Sie ein SBOM, fordern Sie Signaturen und prüfen Sie Eigentümer-
oder Veröffentlichungswechsel sorgfältig.

## Referenzen

- OWASP A06:2021
- MITRE ATT&CK T1195.002
- NIST SP 800-161r1
- SLSA — Supply-chain Levels for Software Artifacts
