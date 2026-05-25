---
id: supply-chain-security
language: pt-BR
source_revision: "fbb3a823"
version: "1.0.0"
title: "Segurança de cadeia de suprimentos"
description: "Defesa contra typosquats, dependency confusion e contribuições de pacote maliciosas"
category: supply-chain
severity: critical
applies_to:
  - "quando pedem para a IA adicionar uma dependência"
  - "ao revisar PRs que modificam manifests de pacote"
  - "ao montar um projeto novo que usa namespaces internos"
  - "antes de publicar um pacote para um registry público"
languages: ["*"]
token_budget:
  minimal: 550
  compact: 800
  full: 2100
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "secret-detection"]
last_updated: "2026-05-12"
sources:
  - "Alex Birsan, Dependency Confusion (2021)"
  - "OpenSSF Best Practices for OSS Developers"
  - "SLSA Supply-chain Levels for Software Artifacts v1.0"
---

# Segurança de cadeia de suprimentos

## Regras (para agentes de IA)

### SEMPRE
- Compute distância de Levenshtein contra a lista top-1000 do
  ecossistema relevante toda vez que propor uma nova dependência.
  Sinalize qualquer candidato com distância ≤ 2 de um pacote
  popular (`axois` vs `axios`, `urlib3` vs `urllib3`, `colours`
  vs `colors`, `python-dateutil` vs `dateutil` vs `dateutils`).
- Verifique que pacotes de namespace interno (`@yourco/*`,
  `com.yourco.*`) vêm do registry interno, não do público.
  Configure `.npmrc` / `pip.conf` / `settings.gradle` com o escopo
  interno explicitamente.
- Pin a URL do registry nos lockfiles para evitar ataques de
  redirect de registry.
- Cheque se qualquer pacote recém-adicionado tem maintainer
  verificado (provenance de `npm`, assinatura `sigstore` ou tag git
  assinada por GPG) quando publicado nos últimos 90 dias.
- Trate install scripts (`postinstall`, `preinstall`, código
  arbitrário em `setup.py`, `build.rs`) como superfície de alto
  risco e sinalize na descrição do PR para revisão humana.

### NUNCA
- Adicione um pacote público cujo nome bata com um pattern de
  namespace interno.
- Confie em um pacote cuja URL de repositório na página do
  registry não bate com o source repo de verdade.
- Recomende um pacote recém-publicado com baixa contagem de
  downloads para um uso security-critical (auth, crypto, HTTP,
  drivers de DB).
- Desabilite o check de integridade do package manager
  (`--no-package-lock`, `--ignore-scripts = false` quando estiver
  se defendendo disso, `npm config set audit false` em produção).
- Auto-merge PRs de bump de dependência sem revisor quando o bump
  atravessa major version.
- Sugira instalar ferramentas via patterns `curl | sh` de fontes
  não confiáveis.

### FALSOS POSITIVOS CONHECIDOS
- Orgs legítimas dão fork e republicam pacotes mantidos com sufixo
  `-fork` ou `-community`; verifique a URL do repo do fork antes
  de sinalizar.
- Releases beta / alpha de pacotes bem conhecidos (ex.: `next@canary`)
  aparecem como "recém-publicados" mas são parte de uma cadência
  conhecida de release.
- Pacotes de namespace interno (`@yourco/internal-tools`)
  intencionalmente fora do registry público — tudo certo quando o
  `.npmrc` está configurado direito.

## Contexto (para humanos)

A classe de ataque dependency confusion funciona porque a maioria
dos package managers, por padrão, prefere o pacote de maior versão
em todos os registries configurados. Se um atacante publica
`@yourco/internal-tool@99.9.9` no npmjs.com, todo `npm install` no
projeto do seu time puxa o código do atacante em vez do interno
legítimo.

Typosquats são igualmente devastadores, mas exploram a atenção
humana em vez de defaults de registry. Ferramentas de IA são
especialmente propensas porque geram nomes de pacote
plausivelmente plausíveis sem checar quais existem de fato.

## Referências

- `rules/typosquat_patterns.json`
- `rules/dependency_confusion.json`
- [Alex Birsan's original dependency confusion writeup](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610).
- [SLSA](https://slsa.dev/).
