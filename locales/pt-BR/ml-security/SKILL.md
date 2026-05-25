---
id: ml-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de ML / LLM"
description: "Prompt injection, poisoning de modelos, ataques de desserialização, PII em dados de treinamento, vazamentos de segredo em notebooks"
category: prevention
severity: high
applies_to:
  - "ao gerar código que chama uma API de LLM ou constrói um agente movido por LLM"
  - "ao gerar código que carrega modelos de ML do disco / Hub / S3"
  - "ao gerar pipelines de dados que ingerem conteúdo de usuário para fine-tuning"
languages: ["python", "javascript", "typescript", "jupyter", "go"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2700
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Top 10 for LLM Applications 2025"
  - "NIST AI 100-2 (Adversarial Machine Learning)"
  - "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)"
  - "CWE-502, CWE-1039, CWE-1426"
---

# Segurança de ML / LLM

## Regras (para agentes de IA)

### SEMPRE
- Trate toda entrada do modelo — incluindo saídas de tools e
  documentos recuperados realimentados no prompt — como não
  confiável. Prompt injection indireta via uma página web ou
  documento recuperado é o ataque a LLM mais comum em ambiente
  real.
- Sanitize e re-codifique qualquer coisa que o modelo emita antes
  de passar a um sistema downstream: builder de SQL, shell, escritor
  de arquivos, request HTTP, avaliador de código. A saída do
  modelo nunca é chave primária para confiança.
- Force um **schema de saída** com geração estruturada (JSON
  Schema, modo function-call, decoding restrito) quando o próximo
  passo consome a saída programaticamente. Rejeite o que falhar
  validação.
- Mantenha uma allowlist de tools / nomes de função que o modelo
  pode invocar; rejeite qualquer outra invocação. Aplique
  autorização por-tool ao *usuário humano* do agente, não só ao
  modelo.
- Para RAG: carimbe documentos recuperados com proveniência e
  separe "instruções" de "contexto" no prompt; não deixe os dados
  recuperados sobrepor as instruções de sistema.
- Ao carregar modelos, use **safetensors** para PyTorch e Hugging
  Face; use `weights_only=True` com `torch.load` no PyTorch 2.4+;
  nunca carregue arquivos `.pkl` / `.pt` arbitrários de fontes não
  confiáveis.
- Limpe PII, credenciais e segredos dos dados de treinamento — na
  fonte (ingestão), no armazenamento (criptografia + controle de
  acesso) e na saída (filtros / detectores de resposta).
- Rate-limit / cota em cada endpoint apoiado em LLM. Rastreie
  gasto de token por tenant.
- Rastreie cada prompt + versão de modelo + contexto recuperado
  como log de auditoria; redija os segredos antes.

### NUNCA
- `pickle.loads` / `joblib.load` / `dill.loads` / `torch.load` de
  um artefato buscado em runtime de fonte não confiável. Esses
  desserializadores executam código arbitrário por design.
- Concatenar input de usuário direto em um prompt que contém
  instruções de maior confiança: ex.:
  `f"You are a helpful agent. {user_input}"`. Use uma boundary
  templated mais separação explícita por role de sistema.
- Passar uma string derivada de LLM direto a `eval`, `exec`,
  `os.system`, `subprocess(shell=True)`, `vm.runInNewContext` ou
  um `.raw()` de SQL.
- Hardcodar API keys de OpenAI / Anthropic / Cohere em notebooks
  ou arquivos do repo. Use variáveis de ambiente e o skill
  `secret-detection`.
- Guardar exemplos de dados de treinamento contendo PII em
  armazenamento de longo prazo sem consentimento explícito,
  janelas de retenção e APIs de deleção.
- Confiar em parâmetros de modelo fornecidos pelo cliente (nome
  do modelo, system prompt, lista de tools) sem validação no
  servidor — clientes vão fazer downgrade para modelos mais
  baratos / fracos / não autorizados.
- Usar um modelo fine-tuned por um vendor externo sem
  verificação de proveniência / linhagem.
- Cachear respostas de LLM indexadas só pelo texto do prompt —
  isso mistura contextos entre usuários quando prompts
  compartilham prefixos.

### FALSOS POSITIVOS CONHECIDOS
- Notebooks de pesquisa / red-team que intencionalmente exercitam
  prompts de jailbreak vão em um ambiente isolado sem
  credenciais de produção.
- Modelos acadêmicos pré-publicação de autores confiáveis
  costumam ser distribuídos como checkpoints `.pt`; converter
  para safetensors como primeiro passo.
- Pipelines de geração de dados sintéticos podem legitimamente
  produzir saída crua de modelo que é depois commitada —
  garanta que esteja rotulada e revisada para PII / segredos
  alucinados inadvertidos.

## Contexto (para humanos)

O OWASP LLM Top 10 (2025) agrupa os ataques mais comuns em dez
classes; **LLM01 Prompt Injection** e **LLM05 Improper Output
Handling** são as preocupações operacionais principais por
aplicarem-se a praticamente todo deploy agêntico. NIST AI 100-2
enquadra as categorias subjacentes de ML adversarial (evasão,
poisoning, extração); MITRE ATLAS oferece uma visão de
kill-chain.

Este skill assume que Devin (ou qualquer assistente de IA) é quem
constrói a app que usa LLM. Trate a app resultante como uma
fronteira de segurança — mesmo quando o "usuário" é outro agente
de IA.

## Referências

- `rules/prompt_injection_patterns.json`
- `rules/unsafe_deserialization.json`
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- [NIST AI 100-2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf).
- [MITRE ATLAS](https://atlas.mitre.org/).
- [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) — Improper Validation of Generative AI Output.
