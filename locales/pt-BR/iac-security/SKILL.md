---
id: iac-security
language: pt-BR
source_revision: "afe376a8"
version: "1.0.0"
title: "Segurança de Infrastructure-as-Code"
description: "Regras de hardening para Terraform, CloudFormation e Pulumi: state, providers, drift, segredos"
category: hardening
severity: high
applies_to:
  - "ao gerar Terraform / Pulumi / CloudFormation"
  - "ao revisar mudanças de IaC em PR"
  - "ao configurar uma nova conta ou workspace de cloud"
languages: ["hcl", "yaml", "json", "typescript", "python", "go"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2500
rules_path: "checklists/"
related_skills: ["infrastructure-security", "container-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "CIS Benchmarks (AWS, Azure, GCP)"
  - "HashiCorp Terraform Best Practices"
  - "NIST SP 800-53 Rev. 5 (CM-6, CM-8, SC-28)"
  - "OWASP IaC Security Top 10"
---

# Segurança de Infrastructure-as-Code

## Regras (para agentes de IA)

### SEMPRE
- Fixe cada provider/módulo em uma versão exata ou em uma restrição
  pessimista (`~> 5.42`); nunca `>= 0` ou um `latest` sem pin.
- Configure um **backend remoto** com criptografia em repouso,
  locking de state no lado servidor e versionamento (Terraform: `s3`
  + tabela de lock no DynamoDB com `kms_key_id`; Pulumi: o backend
  gerenciado ou `s3://?kmskey=`; CloudFormation: gerenciado pela
  AWS).
- Criptografe por padrão cada recurso persistente com uma chave KMS
  gerenciada pelo cliente: buckets S3, volumes EBS, RDS, EFS,
  DynamoDB, SQS, SNS, log groups do CloudWatch.
- Marque cada recurso com `owner`, `environment`, `cost-center` e
  `data-classification` via um bloco de default tags.
- Rode `terraform plan` (ou `pulumi preview`,
  `aws cloudformation deploy --no-execute-changeset`) na CI e exija
  aprovação humana antes do `apply` em stacks de produção.
- Adicione um job de detecção de drift que rode diariamente e abra
  uma issue quando o estado real do cloud divergir do código
  (Terraform Cloud drift detection, `pulumi refresh`,
  `cfn-drift-detect`).
- Use IAM Conditions para limitar cada role: `aws:SourceArn`,
  `aws:SourceAccount`, `aws:PrincipalOrgID`, e policies de acesso
  TLS-only em storage.

### NUNCA
- Hardcode credenciais do provider no código ou em `.tfvars`
  (`access_key`, `secret_key`, `client_secret`,
  `service_account_key`). Use federação OIDC vinda da CI, o serviço
  de metadata da instância do provider, ou um secret manager.
- Commite `terraform.tfstate`, `terraform.tfstate.backup`,
  `.pulumi/`, ou qualquer `*.tfvars` contendo segredos reais. Eles
  contêm segredos em texto plano mesmo que o código referencie
  variáveis.
- Use `local_exec` / `null_resource` para buscar segredos na hora do
  apply e enfiar no state. O state é texto plano consultável por
  qualquer um com acesso de leitura ao backend.
- Abra security groups / regras de firewall para `0.0.0.0/0` nas
  portas 22, 3389, 3306, 5432, 1433, 6379, 27017, 9200, 11211 —
  nem mesmo em "é só dev". Use bastion ou VPN.
- Conceda policies IAM `*:*` (ação wildcard em recurso wildcard).
  Use `iam:PassRole` com ARNs de recurso explícitos.
- Desabilite a verificação TLS do provider (`skip_tls_verify`,
  `insecure = true`).
- Use `count = 0` para "soft-deletar" recursos que você na verdade
  quer fora — destrua-os.

### FALSOS POSITIVOS CONHECIDOS
- Bastion hosts intencionalmente expostos na porta 22 para a
  internet com configurações endurecidas não são o mesmo risco que
  abrir o RDS para o mundo. Documente a exceção inline.
- Distribuições CloudFront públicas, listeners de ALB em 80/443, API
  Gateways e URLs de funções Lambda que *são* feitos para serem
  voltados à internet.
- Recursos de bootstrap (o bucket S3 e a tabela de lock do DynamoDB
  que o próprio backend usa) precisam existir antes do state remoto
  poder existir; esse ciclo ovo-e-galinha geralmente é bootstrapado
  com um backend `local` único, que depois é migrado.

## Contexto (para humanos)

Erros de IaC escalam: um único módulo ruim recebe `terraform apply`
em centenas de contas. As classes de problema que cobrimos aqui —
vazamentos de segredo via state, exposição de rede sem limite, IAM
wildcard, drift — são exatamente o que CIS e as revisões
well-architected dos próprios cloud providers mais sinalizam.
Assistentes de IA são particularmente propensos a gerar Terraform
"funciona na minha máquina" que não fixa nada e usa state local;
este skill é o contrapeso.

## Referências

- `checklists/terraform_hardening.yaml`
- `checklists/cloudformation_hardening.yaml`
- [CIS Benchmark for Amazon Web Services Foundations](https://www.cisecurity.org/benchmark/amazon_web_services).
- [Terraform Recommended Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices).
- [NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final).
