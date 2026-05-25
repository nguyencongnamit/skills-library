---
id: cicd-security
language: pt-BR
source_revision: "4c215e6f"
version: "1.0.0"
title: "Segurança de pipelines CI/CD"
description: "Endurecer GitHub Actions, GitLab CI e pipelines similares contra ataques de supply chain, exfiltração de segredos e abusos do tipo pwn-request"
category: prevention
severity: critical
applies_to:
  - "ao escrever ou revisar arquivos de workflow de CI/CD"
  - "ao adicionar uma action / imagem / script de terceiros a um pipeline"
  - "ao plugar credenciais de cloud ou registry no CI"
  - "ao triar um suspeito comprometimento de pipeline"
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

# Segurança de pipelines CI/CD

## Regras (para agentes de IA)

### SEMPRE
- Fixe toda GitHub Action de terceiros por **SHA de commit** (40
  caracteres completos), não por tag — tags podem ser republicadas. O
  mesmo vale para referências `include:` do GitLab CI e workflows
  reutilizáveis. Renovate / Dependabot podem manter os pins por SHA
  frescos.
- Declare `permissions:` no nível do workflow ou do job e use padrão
  `contents: read`. Conceda escopos adicionais (`id-token: write`,
  `packages: write` etc.) job a job, nunca workflow-wide.
- Use **OIDC** (`id-token: write` + trust policy do provedor cloud)
  para credenciais cloud de curta duração. Nunca armazene chaves AWS /
  GCP / Azure de longa duração como GitHub Secrets.
- Trate `pull_request_target`, `workflow_run` e qualquer job
  `pull_request` que use `actions/checkout` com
  `ref: ${{ github.event.pull_request.head.ref }}` como **contexto
  confiável sobre código não confiável**. Ou não rode, ou rode sem
  segredos e sem tokens de escrita.
- Passe toda expressão não confiável (`${{ github.event.* }}`) primeiro
  por uma variável de ambiente; nunca interpole diretamente no corpo
  `run:` — esse é o sink canônico de script-injection do GitHub
  Actions.
- Assine artefatos de release (Sigstore / cosign) e publique
  atestações de provenance SLSA. Verifique a provenance em qualquer
  pipeline consumidor que baixe o artefato.
- Defina `runs-on` para uma imagem de runner endurecida e fixe a versão
  do runner. StepSecurity Harden-Runner em modo audit (ou um firewall
  de egress equivalente) é recomendado para qualquer workflow que
  manipule segredos.
- Trate `npm install`, `pip install`, `go install`, `cargo install` e
  `docker pull` invocados em CI como execução de código não confiável.
  Rode com `--ignore-scripts` (npm/yarn), lockfiles fixados, allowlists
  de registry e tokens com privilégio mínimo por job.

### NUNCA
- Fixe uma action de terceiros por tag flutuante (`@v1`, `@main`,
  `@latest`). O incidente tj-actions/changed-files de março de 2025
  exfiltrou segredos de mais de 23.000 repositórios justamente porque
  os consumidores usavam tags flutuantes.
- `curl | bash` (ou `wget -O- | sh`) qualquer script de instalação no
  CI. O comprometimento do bash uploader do Codecov em 2021 exfiltrou
  env vars para um atacante por ~10 semanas porque milhares de
  pipelines rodavam `bash <(curl https://codecov.io/bash)`. Sempre
  baixe, verifique checksum, depois execute.
- Eco de segredos em logs, mesmo em falha. Use `::add-mask::` para
  qualquer segredo computado em runtime e cheque novamente com a
  busca em logs de workflow do GitHub.
- Permita que workflows rodem em PRs de forks com
  `pull_request_target` se algum job toca um token com escopo de
  escrita ou um segredo. A combinação é o padrão canônico "pwn
  request" documentado pelo GitHub Security Lab.
- Cacheie estado mutável (ex.: `~/.npm`, `~/.cargo`, `~/.gradle`)
  usando apenas `os` como chave. Um hit de cache entre jobs é uma
  superfície de ataque cross-tenant — chaveie por hash de lockfile e
  escope na ref do workflow.
- Confie em downloads de artefatos de runs de workflow arbitrários sem
  verificar o workflow de origem + SHA do commit. Envenenamento de
  build-cache funciona via reuso de artefatos sem escopo.
- Armazene segredos em variáveis de repositório (`vars.*`) — são texto
  plano para quem tem acesso de leitura. Apenas `secrets.*` é gated
  por scanning e regras de escopo.

### FALSOS POSITIVOS CONHECIDOS
- Actions first-party da mesma organização que você espelha ou forka
  in-house podem legitimamente ser fixadas por tag se a org impõe tags
  assinadas + branch-protection no repo da action.
- Pipelines de dados públicos que não manipulam segredos nem produzem
  artefato assinado (ex.: link-checkers noturnos) não precisam de OIDC
  nem provenance SLSA, e podem usar tags flutuantes sem impacto
  prático.
- `pull_request_target` é legítimo para bots de label / triage que só
  chamam a API do GitHub com os escopos mínimos necessários, não fazem
  checkout do código do PR e não expõem segredos no env.

## Contexto (para humanos)

CI/CD é hoje o alvo único mais lucrativo da supply chain. Um pipeline
roda código confiável contra credenciais confiáveis e registries
confiáveis — comprometê-lo uma vez dá acesso a todo consumidor a
jusante de todo artefato que ele produz. O comprometimento do Codecov
em 2021, o incidente SolarWinds em 2021, o envenenamento do pipeline
de release da Ultralytics no PyPI em 2024 e a exfiltração em massa do
tj-actions/changed-files em 2025 dependeram todos de mudanças não
autenticadas em scripts ou actions consumidos pelo CI.

A maior parte das defesas é mecânica: fixar por SHA, minimizar
permissões, usar OIDC, assinar artefatos, verificar provenance. O
difícil é impor isso em escala organizacional. OpenSSF Scorecard
automatiza as checagens das defesas mecânicas e integra com branch
protection.

Esta skill enfatiza as fraquezas de design pattern (pwn requests,
script injection, curl-pipe-bash, tags flutuantes, download de
artefato não confiável) porque são os padrões que o YAML de workflow
gerado por IA mais reinventa.

## Referências

- `checklists/github_actions_hardening.yaml`
- `checklists/gitlab_ci_hardening.yaml`
- [OpenSSF Scorecard](https://github.com/ossf/scorecard).
- [SLSA v1.0 Build Track](https://slsa.dev/spec/v1.0/levels).
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).
- [StepSecurity — tj-actions/changed-files attack analysis](https://www.stepsecurity.io/blog/tj-actions-changed-files-attack-analysis).
- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html).
