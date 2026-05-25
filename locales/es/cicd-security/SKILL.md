---
id: cicd-security
language: es
source_revision: "4c215e6f"
version: "1.0.0"
title: "Seguridad de pipelines CI/CD"
description: "Endurecer GitHub Actions, GitLab CI y pipelines similares contra ataques de cadena de suministro, exfiltración de secretos y abusos tipo pwn-request"
category: prevention
severity: critical
applies_to:
  - "al escribir o revisar archivos de workflow CI/CD"
  - "al añadir una acción / imagen / script de terceros a un pipeline"
  - "al conectar credenciales de cloud o registry al CI"
  - "al triar un supuesto compromiso de pipeline"
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

# Seguridad de pipelines CI/CD

## Reglas (para agentes de IA)

### SIEMPRE
- Fijar cada GitHub Action de terceros por **SHA de commit** (40 caracteres
  completos), no por tag — los tags pueden re-publicarse. Lo mismo aplica a
  referencias `include:` y workflows reutilizables de GitLab CI. Renovate /
  Dependabot pueden mantener frescas las fijaciones por SHA.
- Declarar `permissions:` a nivel de workflow o job y por defecto solo
  `contents: read`. Conceder scopes adicionales (`id-token: write`,
  `packages: write`, etc.) job por job, nunca a todo el workflow.
- Usar **OIDC** (`id-token: write` + política de confianza del proveedor cloud)
  para credenciales cloud de vida corta. Nunca almacenar claves AWS / GCP /
  Azure de larga vida como GitHub Secrets.
- Tratar `pull_request_target`, `workflow_run` y cualquier job de
  `pull_request` que use `actions/checkout` con
  `ref: ${{ github.event.pull_request.head.ref }}` como
  **contexto-confiable-sobre-código-no-confiable**. O no los ejecutes, o
  ejecútalos sin secretos y sin tokens de escritura.
- Pasar toda expresión no confiable (`${{ github.event.* }}`) primero a través
  de una variable de entorno; nunca interpolarla directamente en el cuerpo
  `run:` — es el canonical sink de script-injection de GitHub Actions.
- Firmar artefactos de release (Sigstore / cosign) y publicar atestaciones de
  procedencia SLSA. Verificar la procedencia en cualquier pipeline consumidor
  que descargue el artefacto.
- Fijar `runs-on` a una imagen de runner endurecida y fijar la versión del
  runner. Se recomienda StepSecurity Harden-Runner en modo audit (o un
  firewall de egress equivalente) para cualquier workflow que maneje secretos.
- Tratar `npm install`, `pip install`, `go install`, `cargo install` y
  `docker pull` invocados en CI como ejecución de código no confiable.
  Ejecutar con `--ignore-scripts` (npm/yarn), lockfiles fijados, allowlists
  de registry y tokens de mínimo privilegio por job.

### NUNCA
- Fijar una acción de terceros por tag flotante (`@v1`, `@main`, `@latest`).
  El incidente de tj-actions/changed-files de marzo 2025 exfiltró secretos de
  más de 23.000 repositorios específicamente porque los consumidores usaban
  tags flotantes.
- `curl | bash` (o `wget -O- | sh`) cualquier script de instalación en CI. El
  compromiso del bash uploader de Codecov de 2021 exfiltró env vars a un
  atacante durante ~10 semanas porque miles de pipelines ejecutaban
  `bash <(curl https://codecov.io/bash)`. Descargar, verificar checksum y
  luego ejecutar.
- Echo de secretos a logs, incluso en fallo. Usa `::add-mask::` para
  cualquier secreto computado en tiempo de ejecución y comprueba con la
  búsqueda de logs del workflow de GitHub.
- Permitir que workflows corran en PRs de forks con `pull_request_target` si
  algún job toca un token con permiso de escritura o un secreto. La
  combinación es el patrón canónico "pwn request" documentado por GitHub
  Security Lab.
- Cachear estado mutable (p. ej. `~/.npm`, `~/.cargo`, `~/.gradle`) usando
  solo `os` como key. Un hit de caché entre jobs es una superficie de ataque
  entre tenants — keyea por hash de lockfile y limita al workflow ref.
- Confiar en descargas de artefactos desde ejecuciones arbitrarias de
  workflow sin verificar el workflow origen + SHA de commit. El envenenado
  de build-cache funciona a través de la reutilización de artefactos sin
  scope.
- Almacenar secretos en variables de repositorio (`vars.*`) — son texto
  plano para cualquiera con acceso de lectura. Solo `secrets.*` está protegido
  por el escaneo y las reglas de scope.

### FALSOS POSITIVOS CONOCIDOS
- Acciones de primera parte de la misma organización que espejas o forkeas
  internamente pueden fijarse legítimamente por tag si la org aplica tags
  firmados + branch-protection en el repo de la acción.
- Pipelines de datos públicos que no manejan secretos ni producen artefactos
  firmados (p. ej. comprobadores nocturnos de enlaces) no necesitan OIDC ni
  procedencia SLSA, y pueden usar tags flotantes sin impacto práctico.
- `pull_request_target` es legítimo para bots de etiqueta / triage que solo
  llaman a la API de GitHub con los scopes mínimos necesarios, no hacen
  checkout del código del PR y no exponen secretos en el entorno.

## Contexto (para humanos)

CI/CD es hoy el blanco más lucrativo de cadena de suministro. Un pipeline
ejecuta código confiable contra credenciales confiables y registries
confiables — comprometerlo una sola vez da acceso a todos los consumidores
de todos los artefactos que produce. El compromiso de Codecov de 2021, el
incidente SolarWinds de 2021, el envenenado del pipeline de release de
Ultralytics PyPI de 2024 y la exfiltración masiva de tj-actions/changed-files
de 2025 todos se apoyaron en cambios no autenticados a scripts o acciones
consumidos por CI.

La mayoría de las defensas son mecánicas: fijar por SHA, minimizar
permisos, usar OIDC, firmar artefactos, verificar procedencia. Lo difícil
es hacerlas cumplir a escala de organización. OpenSSF Scorecard automatiza
los chequeos para las defensas mecánicas y se integra con branch protection.

Esta skill enfatiza las debilidades de patrón de diseño (pwn requests,
script injection, curl-pipe-bash, tags flotantes, descarga de artefactos no
confiables) porque son los patrones que más reinventa el YAML de workflow
generado por IA.

## Referencias

- `checklists/github_actions_hardening.yaml`
- `checklists/gitlab_ci_hardening.yaml`
- [OpenSSF Scorecard](https://github.com/ossf/scorecard).
- [SLSA v1.0 Build Track](https://slsa.dev/spec/v1.0/levels).
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).
- [StepSecurity — tj-actions/changed-files attack analysis](https://www.stepsecurity.io/blog/tj-actions-changed-files-attack-analysis).
- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html).
