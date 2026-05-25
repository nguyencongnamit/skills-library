---
id: compliance-awareness
language: pt-BR
source_revision: "8e503523"
version: "1.0.0"
title: "Consciência de conformidade"
description: "Mapear o código gerado contra controles OWASP, CWE e SANS Top 25 para rastreabilidade"
category: compliance
severity: medium
applies_to:
  - "ao gerar código em ambientes regulados"
  - "ao escrever comentários ou documentação relevantes para auditoria"
  - "ao refatorar código que cruza fronteiras de conformidade (PII, PHI, escopo PCI)"
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

# Consciência de conformidade

## Regras (para agentes de IA)

### SEMPRE
- Marque funções que manipulam dados PII / PHI / PCI com um comentário
  que indique a classificação (ex.: `// classification: PII`).
- Logue eventos de auditoria para ações relevantes à segurança (login,
  mudança de permissão, exportação de dados, operações admin) — registre
  quem, o quê, quando, NÃO o payload sensível.
- Identifique a categoria CWE / OWASP de código relevante à segurança
  nos comentários quando a convenção do time for incluir rastreabilidade
  (`// addresses CWE-79 — XSS`).
- Para escopo PCI, segregue o código que manipula dados de cartão em
  módulos com nomes claros, para que as fronteiras do escopo fiquem
  visíveis.
- Para cargas HIPAA, prefira criptografia em repouso E em trânsito, com
  gerenciamento de chaves documentado.

### NUNCA
- Inclua PII / PHI / PCI em mensagens de log, mensagens de erro ou
  eventos de telemetria.
- Armazene números de cartão, CVVs ou dados completos de tarja
  magnética fora de um serviço de tokenização conforme PCI DSS.
- Misture código que manipula PII em módulos utilitários gerais sem
  classificação explícita.
- Gere código que processa dados pessoais de residentes da UE sem
  considerar as obrigações do GDPR (direito ao esquecimento, minimização
  de dados, base legal).
- Sugira workarounds que burlam controles de conformidade "para
  desenvolvimento" — esses workarounds sempre vazam para produção.

### FALSOS POSITIVOS CONHECIDOS
- Logs dos *tipos* de dado acessados ("usuário acessou registro de
  reivindicação") geralmente são OK; a regra é contra logar o *conteúdo*
  de campos sensíveis.
- Fixtures de teste com dados claramente falsos (telefones `555-0100`,
  PAN `4111-1111-1111-1111`, `John Doe`) não são PII.
- A retenção de logs de auditoria é intencionalmente longa (geralmente
  anos) e não deve ser filtrada por varreduras gerais de retenção.

## Contexto (para humanos)

Frameworks de conformidade (PCI DSS, HIPAA, SOC 2, ISO 27001, GDPR)
prescrevem controles mas não dizem ao desenvolvedor que código escrever.
Esta skill cobre essa lacuna anexando orientação relevante aos passos de
geração de IA, para que o código resultante seja audit-friendly por
padrão.

## Referências

- `frameworks/owasp_mapping.yaml`
- `frameworks/cwe_mapping.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/).
