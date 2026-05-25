---
id: infrastructure-security
language: pt-BR
source_revision: "fbb3a823"
version: "1.0.0"
title: "Segurança de infraestrutura"
description: "Aplicar regras de hardening para Kubernetes, Docker e infrastructure-as-code em Terraform"
category: hardening
severity: high
applies_to:
  - "ao gerar conteúdo de Dockerfile"
  - "ao gerar manifests de Kubernetes ou charts de Helm"
  - "ao gerar Terraform ou CloudFormation"
  - "ao revisar PRs de IaC"
languages: ["yaml", "hcl", "dockerfile"]
token_budget:
  minimal: 650
  compact: 950
  full: 2500
rules_path: "checklists/"
related_skills: ["api-security", "compliance-awareness"]
last_updated: "2026-05-12"
sources:
  - "CIS Kubernetes Benchmark"
  - "CIS Docker Benchmark"
  - "NSA/CISA Kubernetes Hardening Guidance"
  - "HashiCorp Terraform Security Best Practices"
---

# Segurança de infraestrutura

## Regras (para agentes de IA)

### SEMPRE
- Fixe imagens base por digest (`FROM image@sha256:...`) ao construir
  containers para produção. Tags são mutáveis; digests não.
- Rode containers como um `USER` não-root diferente de `0`. Adicione
  `securityContext: runAsNonRoot: true` aos pod specs do K8s.
- Defina `requests` E `limits` explícitos de recursos do Kubernetes
  (`requests.cpu`, `requests.memory`, `limits.cpu`,
  `limits.memory`).
- Faça drop de todas as capabilities do Linux e re-adicione só o que
  for necessário (`securityContext.capabilities.drop: ["ALL"]`).
- Marque os filesystems como read-only
  (`securityContext.readOnlyRootFilesystem: true`) quando o workload
  não precisar legitimamente de acesso de escrita.
- Habilite criptografia em repouso (`enable_kms_encryption`,
  `kms_key_id`, `server_side_encryption_configuration`) para buckets
  S3, volumes EBS, RDS, DynamoDB.
- Defina `block_public_access` em cada bucket S3 a não ser que o
  workload realmente sirva conteúdo público.
- Aplique o princípio do privilégio mínimo às policies IAM: nomeie
  ações e recursos explícitos; evite `*:*` e `Resource: "*"` fora de
  policies admin intencionais.

### NUNCA
- Use `latest` como tag de imagem em manifests de produção.
- Rode um container com flag `--privileged` ou
  `securityContext.privileged: true`.
- Monte o `/var/run/docker.sock` do host dentro de um container.
- Exponha serviços do Kubernetes com `type: LoadBalancer`
  diretamente para a internet sem um ingress controller, WAF ou
  camada de autenticação na frente.
- Hardcode chaves de AWS / chaves de service-account de GCP / client
  secrets de Azure no IaC. Use IRSA, Workload Identity do GKE,
  managed identities do Azure, ou o equivalente nativo da
  plataforma.
- Crie buckets S3 com `acl = "public-read"` para buckets contendo
  algo diferente de assets intencionalmente públicos.
- Permita ingress `0.0.0.0/0` em portas de banco de dados, SSH, RDP
  ou admin.
- Desabilite `node_to_node_encryption` em Elasticsearch /
  OpenSearch.

### FALSOS POSITIVOS CONHECIDOS
- Fixar digest de imagem nem sempre é prático em ambientes de dev /
  preview — fixar por tag (ex.: `node:20.11.1-alpine`) é aceitável
  ali.
- `Resource: "*"` é aceitável em policies que estejam documentadas
  como admin-only com constraints `Condition` explícitos.
- `runAsNonRoot: false` é aceitável quando o workload realmente
  exige root (ex.: bindar à porta 80, certas ferramentas de rede).
  Documente o porquê.

## Contexto (para humanos)

Infraestrutura mal configurada é a causa dominante de breaches em
cloud. Os padrões acima codificam os itens de benchmark CIS mais
violados como regras que a IA aplica durante a geração, não depois
do deploy.

## Referências

- `checklists/k8s_hardening.yaml`
- `checklists/docker_security.yaml`
- `checklists/terraform_security.yaml`
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF).
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
