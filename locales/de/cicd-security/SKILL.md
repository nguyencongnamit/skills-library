---
id: cicd-security
language: de
source_revision: "4c215e6f"
version: "1.0.0"
title: "CI/CD-Pipeline-Sicherheit"
description: "GitHub Actions, GitLab CI und ähnliche Pipelines gegen Supply-Chain-Angriffe, Secret-Exfiltration und pwn-request-artige Missbräuche härten"
category: prevention
severity: critical
applies_to:
  - "beim Schreiben oder Reviewen von CI/CD-Workflow-Dateien"
  - "beim Hinzufügen einer Drittanbieter-Action / -Image / -Script zu einer Pipeline"
  - "beim Verdrahten von Cloud- oder Registry-Credentials in CI"
  - "bei der Triage eines vermuteten Pipeline-Kompromisses"
languages: ["yaml", "shell", "*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "checklists/"
related_skills: ["supply-chain-security", "secret-detection", "container-security"]
last_updated: "2026-05-13"
sources:
  - "OpenSSF Scorecard — Pinned-Dependencies / Token-Permissions"
  - "SLSA v1.0 Build Track"
  - "GitHub Security Lab — Preventing pwn requests"
  - "StepSecurity — tj-actions/changed-files attack analysis"
  - "CWE-1395: Dependency on Vulnerable Third-Party Component"
---

# CI/CD-Pipeline-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Jede Drittanbieter-GitHub-Action per **Commit-SHA** (volle 40 Zeichen)
  anpinnen, nicht per Tag — Tags können neu gepusht werden. Dasselbe gilt
  für GitLab-CI-`include:`-Referenzen und Reusable Workflows. Renovate /
  Dependabot können die SHA-Pins aktuell halten.
- `permissions:` auf Workflow- oder Job-Ebene deklarieren und auf
  `contents: read` als Default beschränken. Zusätzliche Scopes
  (`id-token: write`, `packages: write` usw.) job-weise vergeben, nie
  workflow-weit.
- **OIDC** (`id-token: write` + Trust Policy des Cloud-Providers) für
  kurzlebige Cloud-Credentials verwenden. Niemals langlebige AWS- / GCP- /
  Azure-Keys als GitHub Secrets ablegen.
- `pull_request_target`, `workflow_run` und jeden `pull_request`-Job, der
  `actions/checkout` mit `ref: ${{ github.event.pull_request.head.ref }}`
  verwendet, als **vertrauenswürdigen-Kontext-auf-nicht-vertrauenswürdigem-
  Code** behandeln. Entweder gar nicht laufen lassen oder ohne Secrets und
  ohne Write-Token.
- Jeden nicht vertrauenswürdigen Ausdruck (`${{ github.event.* }}` ) erst
  durch eine Environment-Variable schleifen; niemals direkt in den `run:`-
  Body interpolieren — das ist der kanonische Script-Injection-Sink von
  GitHub Actions.
- Release-Artefakte signieren (Sigstore / cosign) und SLSA-Provenance-
  Attestierungen veröffentlichen. Provenance in jeder Consumer-Pipeline
  verifizieren, die das Artefakt zieht.
- `runs-on` auf ein gehärtetes Runner-Image setzen und die Runner-Version
  pinnen. StepSecurity Harden-Runner im Audit-Modus (oder eine
  gleichwertige Egress-Firewall) für jeden Workflow mit Secret-Zugriff ist
  empfohlen.
- `npm install`, `pip install`, `go install`, `cargo install` und
  `docker pull` in CI als nicht vertrauenswürdige Code-Ausführung
  behandeln. Mit `--ignore-scripts` (npm/yarn), gepinnten Lockfiles,
  Registry-Allowlists und Least-Privilege-Token pro Job laufen lassen.

### NIE
- Eine Drittanbieter-Action per fließendem Tag (`@v1`, `@main`, `@latest`)
  anpinnen. Der tj-actions/changed-files-Vorfall im März 2025 exfiltrierte
  Secrets aus 23.000+ Repositories genau weil Consumer fließende Tags
  nutzten.
- `curl | bash` (oder `wget -O- | sh`) ein beliebiges Installer-Skript in
  CI ausführen. Der Codecov-Bash-Uploader-Kompromiss 2021 exfiltrierte
  Env-Vars über ~10 Wochen, weil Tausende Pipelines
  `bash <(curl https://codecov.io/bash)` liefen. Immer erst herunterladen,
  Checksum prüfen, dann ausführen.
- Secrets in Logs ausgeben, selbst bei Fehlschlag. `::add-mask::` für
  jedes zur Laufzeit berechnete Secret verwenden und mit der GitHub-
  Workflow-Log-Suche gegenprüfen.
- Workflows auf Fork-PRs mit `pull_request_target` laufen lassen, wenn
  irgendein Job ein Write-Token oder Secret berührt. Diese Kombination
  ist das von GitHub Security Lab dokumentierte kanonische
  "pwn-request"-Muster.
- Mutable State (z. B. `~/.npm`, `~/.cargo`, `~/.gradle`) nur per `os` als
  Cache-Key cachen. Ein Cache-Hit über Jobs hinweg ist eine
  Cross-Tenant-Angriffsfläche — Lockfile-Hash als Key nehmen und auf die
  Workflow-Ref begrenzen.
- Artefakt-Downloads aus beliebigen Workflow-Runs vertrauen, ohne den
  Quell-Workflow + Commit-SHA zu verifizieren. Build-Cache-Poisoning
  funktioniert über unscoped Artefakt-Wiederverwendung.
- Secrets in Repository-Variablen (`vars.*`) speichern — sie sind
  Klartext für jeden mit Read-Zugriff. Nur `secrets.*` ist durch
  Secret-Scanning und Scope-Regeln geschützt.

### BEKANNTE FALSCH-POSITIVE
- First-Party-Actions in derselben Organisation, die du intern spiegelst
  oder forkst, dürfen legitim per Tag gepinnt sein, wenn die Org signierte
  Tags + Branch-Protection auf dem Action-Repo durchsetzt.
- Public-Data-Pipelines, die keine Secrets behandeln und kein signiertes
  Artefakt produzieren (z. B. nächtliche Link-Checker), brauchen weder
  OIDC noch SLSA-Provenance und können fließende Tags ohne praktische
  Auswirkung verwenden.
- `pull_request_target` ist legitim für Label-/Triage-Bots, die nur die
  GitHub-API mit minimal nötigen Scopes aufrufen, keinen PR-Code
  auschecken und keine Secrets im Env exponieren.

## Kontext (für Menschen)

CI/CD ist heute das lukrativste Einzel-Ziel der Supply Chain. Eine
Pipeline führt vertrauenswürdigen Code gegen vertrauenswürdige Credentials
und vertrauenswürdige Registries aus — sie einmal zu kompromittieren gibt
Zugriff auf jeden Downstream-Konsumenten jedes produzierten Artefakts.
Der Codecov-Kompromiss 2021, der SolarWinds-Vorfall 2021, die 2024er
Vergiftung der Ultralytics-PyPI-Release-Pipeline und die 2025er Massen-
Exfiltration von tj-actions/changed-files hingen alle an
nicht authentifizierten Änderungen an CI-konsumierten Skripten oder
Actions.

Die meisten Abwehrmaßnahmen sind mechanisch: per SHA pinnen, Permissions
minimieren, OIDC nutzen, Artefakte signieren, Provenance verifizieren.
Schwer ist es, sie organisationsweit durchzusetzen. OpenSSF Scorecard
automatisiert die Prüfungen für die mechanischen Defenses und integriert
sich mit Branch Protection.

Dieser Skill betont die Design-Pattern-Schwächen (pwn requests, Script
Injection, curl-pipe-bash, fließende Tags, untrusted Artefakt-Download),
weil das die Muster sind, die KI-generiertes Workflow-YAML am häufigsten
neu erfindet.

## Referenzen

- `checklists/github_actions_hardening.yaml`
- `checklists/gitlab_ci_hardening.yaml`
- [OpenSSF Scorecard](https://github.com/ossf/scorecard).
- [SLSA v1.0 Build Track](https://slsa.dev/spec/v1.0/levels).
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).
- [StepSecurity — tj-actions/changed-files attack analysis](https://www.stepsecurity.io/blog/tj-actions-changed-files-attack-analysis).
- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html).
