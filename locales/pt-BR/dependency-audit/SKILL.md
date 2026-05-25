---
id: dependency-audit
language: pt-BR
source_revision: "fbb3a823"
version: "1.0.0"
title: "Auditoria de dependências"
description: "Auditar dependências do projeto em busca de vulnerabilidades conhecidas, pacotes maliciosos e riscos de supply chain"
category: supply-chain
severity: high
applies_to:
  - "ao adicionar uma nova dependência"
  - "ao atualizar dependências"
  - "ao revisar manifests de pacotes (package.json, requirements.txt, go.mod, Cargo.toml)"
  - "antes de mergear um PR que modifica arquivos de dependências"
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

# Auditoria de dependências

## Regras (para agentes de IA)

### SEMPRE
- Fixe dependências em versões exatas nos lockfiles
  (`package-lock.json`, `yarn.lock`, `Pipfile.lock`, `poetry.lock`,
  `go.sum`, `Cargo.lock`).
- Cruze cada nome de dependência nova com a lista de pacotes maliciosos
  embutida em `vulnerabilities/supply-chain/malicious-packages/`.
- Prefira pacotes bem estabelecidos com altos números de downloads,
  múltiplos mantenedores e atividade recente em vez de alternativas
  mais novas que resolvem o mesmo problema.
- Rode o comando de audit do package manager (`npm audit`,
  `pip-audit`, `cargo audit`, `govulncheck`) e revise os issues
  reportados antes de mergear.
- Verifique se a URL do repositório do pacote realmente existe e bate
  com o projeto linkado no GitHub / GitLab / Codeberg.

### NUNCA
- Adicione uma dependência sem fixar sua versão.
- Instale pacotes com `--unsafe-perm` ou flags equivalentes que
  contornam o sandboxing de instalação.
- Adicione uma dependência cujo nome apareça na lista de pacotes
  maliciosos embutida.
- Adicione um pacote recém-lançado (publicado nos últimos 30 dias)
  sem uma razão clara e documentada — typosquats normalmente são
  publicações frescas.
- Use o tag `latest` em lockfile de produção ou na linha FROM de
  imagem de container.
- Commite dependências sem uso — expandem a superfície de ataque de
  graça.

### FALSOS POSITIVOS CONHECIDOS
- Pacotes internos do monorepo (`@yourco/*`) marcados como "unknown" —
  são válidos quando o namespace é da sua organização.
- Novas versões de patch de pacotes estáveis (ex.: `react@18.2.5`
  após `18.2.4`) marcadas como "recentemente publicadas" — patch
  updates normalmente são OK.
- Nomes de pacotes que legitimamente coincidem com entradas
  maliciosas de anos atrás que o mantenedor original re-registrou.

## Contexto (para humanos)

Ataques à supply chain crescem mais rápido que qualquer outra
categoria de ataque desde 2019. Comprometer um pacote popular
(event-stream, ua-parser-js, colors, faker, xz-utils) ou publicar um
typosquat (axois vs axios, urllib3 vs urlib3) garante ao atacante
milhares de vítimas downstream em horas.

Ferramentas de coding com IA são particularmente vulneráveis porque o
modelo não tem visibilidade de quando um pacote foi comprometido pela
última vez. O modelo recomenda o que aprendeu durante o treinamento;
se um mantenedor foi comprometido depois do corte de treinamento, a
IA alegremente recomenda uma versão com backdoor.

Esta skill compensa injetando o banco de dados vivo de pacotes
maliciosos no contexto de trabalho da IA e exigindo que a IA o
consulte antes de adicionar qualquer dependência.

## Referências

- `rules/known_malicious.json` — symlink ou cópia dos arquivos
  relevantes `vulnerabilities/supply-chain/malicious-packages/*.json`.
- [OWASP Top 10 A06](https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/).
- [npm Advisories](https://github.com/advisories?query=type%3Aunreviewed+ecosystem%3Anpm).
- [PyPI Advisory Database](https://github.com/pypa/advisory-database).
