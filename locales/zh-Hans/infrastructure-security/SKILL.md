---
id: infrastructure-security
language: zh-Hans
source_revision: "fbb3a823"
version: "1.0.0"
title: "基础设施安全"
description: "对 Kubernetes、Docker 和 Terraform infrastructure-as-code 应用加固规则"
category: hardening
severity: high
applies_to:
  - "在生成 Dockerfile 内容时"
  - "在生成 Kubernetes manifest 或 Helm chart 时"
  - "在生成 Terraform 或 CloudFormation 时"
  - "在审查 IaC PR 时"
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

# 基础设施安全

## 规则（面向 AI 代理）

### 必须
- 为生产环境构建 container 时,要用 digest 固定 base image
  (`FROM image@sha256:...`)。Tag 可变,digest 不可变。
- 用非 root 的 `USER`(不是 `0`)运行 container。给 K8s pod spec 加上
  `securityContext: runAsNonRoot: true`。
- 显式设置 Kubernetes 资源的 `requests` 与 `limits`
  (`requests.cpu`、`requests.memory`、`limits.cpu`、
  `limits.memory`)。
- 丢弃所有 Linux capability,只重新加回真正需要的那些
  (`securityContext.capabilities.drop: ["ALL"]`)。
- 当 workload 合理地不需要写权限时,把 filesystem 标记为只读
  (`securityContext.readOnlyRootFilesystem: true`)。
- 对 S3 bucket、EBS 卷、RDS、DynamoDB 启用静态加密
  (`enable_kms_encryption`、`kms_key_id`、
  `server_side_encryption_configuration`)。
- 除非该 workload 确实就是提供公开内容,否则对每个 S3 bucket 都打
  开 `block_public_access`。
- 对 IAM policy 应用最小权限原则:列出明确的 action 和 resource;在
  不是有意为之的 admin policy 之外,避免 `*:*` 和 `Resource: "*"`。

### 禁止
- 不要在生产 manifest 中把镜像 tag 写成 `latest`。
- 不要用 `--privileged` flag 或 `securityContext.privileged: true`
  运行 container。
- 不要把宿主机的 `/var/run/docker.sock` 挂进 container。
- 不要在前面没有 ingress controller、WAF 或认证层的情况下,用
  `type: LoadBalancer` 把 Kubernetes 服务直接暴露到公网。
- 不要在 IaC 里硬编码 AWS 密钥 / GCP service-account 密钥 / Azure
  client secret。要用 IRSA、GKE Workload Identity、Azure managed
  identity,或平台原生等价物。
- 不要对存放非"刻意公开"内容的 S3 bucket 设置
  `acl = "public-read"`。
- 不要允许数据库、SSH、RDP 或管理端口对 `0.0.0.0/0` 开放 ingress。
- 不要在 Elasticsearch / OpenSearch 上关闭
  `node_to_node_encryption`。

### 已知误报
- 在 dev / preview 环境中,固定镜像 digest 并不总是实用 —— 按 tag
  固定(例如 `node:20.11.1-alpine`)在那里是可以接受的。
- 对那些被文档化为 admin-only 且带有显式 `Condition` 约束的
  policy,`Resource: "*"` 可以接受。
- 当 workload 真的需要 root 时(例如绑定 80 端口、某些网络工具),
  `runAsNonRoot: false` 可以接受。要写明原因。

## 背景(面向人类)

配置错误的基础设施是云上数据泄露最主要的原因。上面这些 pattern 把
最常被违反的 CIS benchmark 项目编码成 AI 在**生成时**(而不是部署
后)就应用的规则。

## 参考

- `checklists/k8s_hardening.yaml`
- `checklists/docker_security.yaml`
- `checklists/terraform_security.yaml`
- [NSA/CISA Kubernetes Hardening Guidance](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF).
- [CIS Docker Benchmark](https://www.cisecurity.org/benchmark/docker).
