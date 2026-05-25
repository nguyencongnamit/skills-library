---
id: iac-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "Infrastructure-as-Code 安全"
description: "Terraform、CloudFormation 和 Pulumi 的加固规则:state、provider、drift、secret"
category: hardening
severity: high
applies_to:
  - "在生成 Terraform / Pulumi / CloudFormation 时"
  - "在 PR 中审查 IaC 变更时"
  - "在配置新的云账号或 workspace 时"
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

# Infrastructure-as-Code 安全

## 规则（面向 AI 代理）

### 必须
- 把每个 provider/模块固定到具体版本或悲观约束(`~> 5.42`);永远不
  要使用 `>= 0` 或未固定的 `latest`。
- 配置带静态加密、服务端 state 锁与版本控制的**远程后端**
  (Terraform:`s3` + 带 `kms_key_id` 的 DynamoDB lock 表;
  Pulumi:托管后端或 `s3://?kmskey=`;CloudFormation:由 AWS
  托管)。
- 默认用客户自管的 KMS 密钥加密每个持久化资源:S3 bucket、EBS 卷、
  RDS、EFS、DynamoDB、SQS、SNS、CloudWatch log group。
- 通过 default tags 块给每个资源打上 `owner`、`environment`、
  `cost-center` 和 `data-classification`。
- 在 CI 里跑 `terraform plan`(或 `pulumi preview`、
  `aws cloudformation deploy --no-execute-changeset`),并在对生产
  stack 执行 `apply` 之前要求人工批准。
- 增加每日运行的 drift 检测作业,当实际云上状态与代码偏离时开 issue
  (Terraform Cloud drift detection、`pulumi refresh`、
  `cfn-drift-detect`)。
- 用 IAM Conditions 限定每个 role:`aws:SourceArn`、
  `aws:SourceAccount`、`aws:PrincipalOrgID`,以及对存储的 TLS-only
  访问 policy。

### 禁止
- 不要把 provider 凭据硬编码到代码或 `.tfvars` 里(`access_key`、
  `secret_key`、`client_secret`、`service_account_key`)。从 CI 用
  OIDC 联邦、用 provider 的实例元数据服务或者用 secret manager。
- 不要提交 `terraform.tfstate`、`terraform.tfstate.backup`、
  `.pulumi/`,或任何带真实 secret 的 `*.tfvars`。即使代码用了变量,
  它们里面也包含明文 secret。
- 不要在 apply 时用 `local_exec` / `null_resource` 拉取 secret 并塞
  进 state。任何对后端有读权限的人都能查询 state,其中是明文。
- 不要把 security group / 防火墙规则对 22、3389、3306、5432、1433、
  6379、27017、9200、11211 等端口开放给 `0.0.0.0/0` —— 哪怕"只是
  dev"。请走堡垒机或 VPN。
- 不要授予 `*:*` 的 IAM policy(在通配资源上做通配动作)。`iam:PassRole`
  要带明确的资源 ARN。
- 不要关闭 provider 的 TLS 校验(`skip_tls_verify`、
  `insecure = true`)。
- 不要用 `count = 0` 来"软删除"实际想要消失的资源 —— 直接销毁。

### 已知误报
- 故意把堡垒机用加固配置暴露在 22 端口的互联网上,与把 RDS 暴露给整
  个世界不是同一风险。在 inline 处文档化例外。
- 公共 CloudFront 分发、80/443 上的 ALB listener、API Gateway、
  Lambda function URL —— 这些本来就是面向互联网的。
- Bootstrap 资源(后端自己用的 S3 bucket 和 DynamoDB lock 表)必须先
  存在才有远程 state;这个先有鸡还是先有蛋的问题通常用一次性的
  `local` 后端来 bootstrap,然后再迁移。

## 背景(面向人类)

IaC 上的错误会被放大:一个糟糕的模块被 `terraform apply` 应用到几百
个账号上。我们这里覆盖的几类问题 —— state 中的 secret 泄漏、无限制的
网络暴露、wildcard IAM、drift —— 正是 CIS 和各云厂商自家的
well-architected 评审最常标记的。AI 助手特别容易生成"在我机器上能跑"
的 Terraform,什么都不 pin 且用本地 state;这个 skill 就是反向的平
衡。

## 参考

- `checklists/terraform_hardening.yaml`
- `checklists/cloudformation_hardening.yaml`
- [CIS Benchmark for Amazon Web Services Foundations](https://www.cisecurity.org/benchmark/amazon_web_services).
- [Terraform Recommended Practices](https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices).
- [NIST SP 800-53 Rev. 5 control catalog](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final).
