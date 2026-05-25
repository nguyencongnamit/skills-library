---
id: iam-best-practices
language: pt-BR
source_revision: "6de0becf"
version: "1.0.0"
title: "Boas práticas de Identity & Access Management"
description: "Desenho IAM com privilégio mínimo, rotação de chaves, enforcement de MFA, assunção de roles e padrões de acesso cross-account para AWS / GCP / Azure / Kubernetes"
category: prevention
severity: critical
applies_to:
  - "ao gerar policies, roles ou documentos de trust IAM"
  - "ao configurar service accounts de CI/CD ou workload identities"
  - "ao revisar criação, rotação ou revogação de access keys"
  - "ao desenhar acesso cross-account ou cross-tenant"
languages: ["hcl", "yaml", "json", "python", "go", "typescript"]
token_budget:
  minimal: 1100
  compact: 1500
  full: 2400
rules_path: "rules/"
related_skills: ["auth-security", "iac-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "NIST SP 800-53 Rev. 5 (AC-2, AC-3, AC-6, AC-17, IA-2, IA-5)"
  - "NIST SP 800-63B (Authenticator Assurance)"
  - "CIS Controls v8 (Controls 5 and 6)"
  - "AWS IAM Best Practices"
  - "Google Cloud IAM Recommender"
  - "Microsoft Azure RBAC Best Practices"
  - "CNCF Kubernetes RBAC Good Practices"
  - "OWASP Cloud Security Top 10"
---

# Boas práticas de Identity & Access Management

## Regras (para agentes de IA)

### SEMPRE
- Conceda as permissões **mínimas** necessárias para o trabalho
  declarado do workload (NIST AC-6). Comece com uma policy
  deny-by-default e adicione ações concretas com ARNs `Resource`
  explícitos; nunca `Action: "*"` combinado com `Resource: "*"`.
- Prefira **workload identity** (IAM roles for service accounts no
  EKS, Workload Identity no GKE, Managed Identity no Azure) em vez de
  access keys de longa duração. Access keys estáticas são exceção,
  não o padrão.
- Exija **MFA** para cada usuário IAM humano, especialmente qualquer
  principal que possa assumir um role privilegiado. Force MFA via
  condição na policy IAM (`aws:MultiFactorAuthPresent: true`), não só
  por configuração no nível do diretório.
- Faça rotação de access keys, service-account keys e signing keys
  num cronograma documentado (≤ 90 dias). Detecte credenciais
  inativas (≥ 90 dias sem uso) e desabilite-as automaticamente.
- Use **assunção de role com `sts:AssumeRole` + ExternalId** para
  trust entre contas. O ExternalId deve ser único por consumidor e
  guardado como segredo em ambas as contas.
- Emita credenciais **com escopo de sessão** com
  `MaxSessionDuration ≤ 1h` para roles humanos e ≤ 12h para roles
  break-glass. Sessões de longa duração derrotam a rotação.
- Separe identidades de **deploy** e de **runtime**. O pipeline de
  CI/CD recebe um role de deploy; o serviço em execução recebe um
  role de runtime distinto sem permissões que mutem IAM.
- Para Kubernetes RBAC, limite `Role` / `RoleBinding` a um único
  namespace; use `ClusterRole` apenas para objetos verdadeiramente
  cluster-wide. Audite bindings de `cluster-admin` em cada PR.
- Logue cada chamada que muta IAM (CloudTrail / Cloud Audit Logs /
  Azure Activity Log) num sink à prova de adulteração. Alerte sobre
  mudanças de policy, `iam:PassRole`, `iam:CreateAccessKey` e
  `sts:AssumeRole` vindos de principals inesperados.
- Para acesso **break-glass** (root, owner, cluster-admin), exija
  aprovação out-of-band (ex.: incidente PagerDuty + ticket) e emita
  alerta imediato em cada uso.
- Marque cada principal IAM com `owner`, `environment` e `purpose`.
  Use essas tags em SCPs / org policies para limitar o raio de
  impacto.

### NUNCA
- Use a conta **root** para operações do dia-a-dia. Credenciais root
  recebem um dispositivo MFA de hardware, ficam guardadas offline e
  só são usadas para o pequeno conjunto de tarefas root-only (ex.:
  fechar conta, mudar plano de suporte).
- Embuta access keys de longa duração no código-fonte, imagens de
  container, AMIs ou variáveis de ambiente de CI quando há workload
  identity disponível.
- Conceda `iam:PassRole` com `Resource: "*"`. Sempre fixe os ARNs
  dos roles que o caller pode passar para serviços downstream.
- Conceda `iam:*` ou `sts:*` a um workload de runtime — essas são
  permissões somente de tempo de deploy.
- Compartilhe um mesmo IAM user entre múltiplos humanos ou serviços.
  Um principal por identidade é o invariante de auditoria.
- Use a managed policy `AdministratorAccess` (ou qualquer `*:*`) de
  forma rotineira; trate-a como anexo exclusivo de break-glass.
- Confie em qualquer assume-role cross-account sem condição
  `ExternalId` para integrações de terceiros (Confused Deputy: AWS
  Security Bulletin 2021).
- Hardcode ARNs / resource IDs de AWS / GCP / Azure em documentos
  de policy sem o escopo correspondente baseado em tags ou caminho
  de organização (quando o número de recursos pode crescer).
- Desabilite MFA de um principal para "corrigir" um problema de
  login — rotacione o dispositivo, não remova a exigência.
- Persista tokens de asserção OIDC / SAML além do TTL declarado.
  Renove por re-asserção, não guardando o token original.

### FALSOS POSITIVOS CONHECIDOS
- `Resource: "*"` é aceitável para operações de leitura intrinseca-
  mente com escopo de conta como `ec2:DescribeRegions` ou
  `sts:GetCallerIdentity` — essas APIs não aceitam ARN de recurso.
- Service-linked roles (ex.: `AWSServiceRoleForAutoScaling`) vêm
  com permissões mais amplas que seus roles custom; isso é por
  design e gerenciado pelo provider.
- Operadores de bootstrap de uma só vez (Terraform runners numa
  conta nova) frequentemente precisam de permissões elevadas;
  limite por tag / SCP e revogue depois que o bootstrap terminar.
- Emuladores de dev local (LocalStack, emulador do GCS) podem
  aceitar qualquer credencial; é propriedade do emulador, não um
  grant real.

## Contexto (para humanos)

Identity & access management é a base de todo controle de segurança
na cloud. Os modos de falha recorrentes são: policies permissivas
demais (`*:*`), access keys de longa duração commitadas no git,
ausência de MFA em contas privilegiadas e trust policies de
`AssumeRole` sem `ExternalId`. São as mesmas causas-raiz
documentadas nos vazamentos de Capital One (2019), Verkada (2021) e
Uber (2022).

Os controles de alta alavancagem são:

1. **Workload identity acima de access keys.** Um pod no EKS que
   assume um role via IRSA nunca precisa de uma credencial que
   possa vazar.
2. **MFA em cada humano, forçada por policy.** Uma senha vazada
   sozinha já não basta para agir.
3. **Grants de privilégio mínimo revisados em tempo de PR.** O
   momento mais barato para restringir uma permissão é quando ela
   está sendo adicionada — não seis meses depois quando um auditor
   pergunta.
4. **Rotação de chaves obrigatória.** Credenciais estáticas
   envelhecem silenciosamente até virarem passivo; automatize a
   rotação para que não seja pulada.
5. **Trust cross-account com ExternalId.** A classe de ataque
   Confused Deputy fica totalmente mitigada por uma convenção de
   ExternalId.

Este skill faz cumprir esses controles quando assistentes de IA
geram policies IAM, documentos de trust ou identidades de CI/CD.

## Referências

- `rules/iam_policy_invariants.json`
- `rules/key_rotation_policy.json`
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- [Google Cloud IAM recommender](https://cloud.google.com/iam/docs/recommender-overview).
- [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
- [CIS Controls v8](https://www.cisecurity.org/controls/v8).
- [CNCF Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).
