---
id: iam-best-practices
language: zh-Hans
source_revision: "6de0becf"
version: "1.0.0"
title: "Identity & Access Management 最佳实践"
description: "面向 AWS / GCP / Azure / Kubernetes 的最小权限 IAM 设计、密钥轮换、MFA 强制、role 假冒(assume)与跨账户访问模式"
category: prevention
severity: critical
applies_to:
  - "在生成 IAM policy、role 或 trust 文档时"
  - "在配置 CI/CD service account 或 workload identity 时"
  - "在审查 access key 的创建、轮换或撤销时"
  - "在设计跨账户或跨租户访问时"
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

# Identity & Access Management 最佳实践

## 规则（面向 AI 代理）

### 必须
- 给 workload 授予完成它声明工作所需的**最少**权限(NIST AC-6)。先
  从 deny-by-default policy 开始,再加入带明确 `Resource` ARN 的具
  体动作;绝不要 `Action: "*"` 搭配 `Resource: "*"`。
- 在长期 access key 之上优先使用 **workload identity**(EKS 上的
  IAM roles for service accounts、GKE Workload Identity、Azure
  Managed Identity)。静态 access key 是例外,不是默认。
- 对每个人类 IAM user,尤其是任何能假冒到特权 role 的 principal,
  强制要求 **MFA**。要通过 IAM policy condition
  (`aws:MultiFactorAuthPresent: true`)强制,而不是只靠目录级设置。
- 按照有文档的节奏轮换 access key、service-account key 和签名密钥
  (≤ 90 天)。检测不活跃的凭据(≥ 90 天未用)并自动禁用。
- 跨账户信任采用 **`sts:AssumeRole` + ExternalId 的 role 假冒**。
  ExternalId 必须按使用方唯一,并在两边账户都作为 secret 存储。
- 给人类 role 发**会话级**凭据,`MaxSessionDuration ≤ 1h`;
  break-glass role ≤ 12h。长会话会架空轮换。
- 分开 **deploy** 与 **runtime** 身份。CI/CD pipeline 拿到一个
  deploy role;运行中的服务拿到另一个 runtime role,且不能有任何会
  修改 IAM 的权限。
- 对于 Kubernetes RBAC,把 `Role` / `RoleBinding` 限定在单个
  namespace;只对真正全 cluster 的对象使用 `ClusterRole`。每个 PR
  都要审计 `cluster-admin` binding。
- 把每一次修改 IAM 的调用都(CloudTrail / Cloud Audit Logs /
  Azure Activity Log)记录到防篡改 sink。对 policy 变更、
  `iam:PassRole`、`iam:CreateAccessKey`,以及来自意外 principal 的
  `sts:AssumeRole` 告警。
- 对 **break-glass** 访问(root、owner、cluster-admin),要求带外
  审批(例如 PagerDuty 事故 + 工单),并对每次使用立即告警。
- 给每个 IAM principal 打上 `owner`、`environment` 和 `purpose`
  标签,并在 SCP / 组织 policy 中用这些标签限制爆炸半径。

### 禁止
- 不要把 **root 账户**用于日常运维。Root 凭据要配硬件 MFA,离线保
  管,只用于必须 root 才能做的少量任务(如关闭账户、修改 support
  plan)。
- 当有 workload identity 可用时,不要把长期 access key 嵌进源码、
  容器镜像、AMI 或 CI 环境变量。
- 不要用 `Resource: "*"` 授予 `iam:PassRole`。一定要 pin 住调用方
  可以传给下游服务的 role ARN。
- 不要把 `iam:*` 或 `sts:*` 授予 runtime workload —— 这些只是
  deploy 期权限。
- 不要让多个人或多个服务共用同一个 IAM user。"一个 principal 对一
  个身份"是审计不变量。
- 不要把 managed policy `AdministratorAccess`(或任何 `*:*`)用于
  常规附挂;把它当作只能 break-glass 时挂的。
- 不要在第三方集成里没有 `ExternalId` 条件就信任跨账户的
  assume-role(Confused Deputy:AWS Security Bulletin 2021)。
- 不要把 AWS / GCP / Azure 的 ARN / 资源 ID 硬编码到 policy 文档
  中,而不配套基于 tag 或组织路径的 scope(当资源数量会增长时)。
- 不要为了"修好"登录问题而关掉某个 principal 的 MFA —— 应轮换设
  备,而不是去掉这项要求。
- 不要把 OIDC / SAML 断言 token 留得比它声明的 TTL 更久。要重新断
  言来刷新,而不是把原始 token 存起来。

### 已知误报
- `Resource: "*"` 对于天然账户级别的只读操作是可以接受的,例如
  `ec2:DescribeRegions` 或 `sts:GetCallerIdentity` —— 这些 API 不接
  受资源 ARN。
- service-linked role(例如 `AWSServiceRoleForAutoScaling`)自带的
  权限比你的自定义 role 更广;那是设计如此,由 provider 管理。
- 一次性 bootstrap operator(在全新账户里跑 Terraform 的 runner)
  通常需要更高权限;用 tag / SCP 限定范围,bootstrap 结束后撤销。
- 本地开发的模拟器(LocalStack、GCS 模拟器)可能接受任何凭据;那是
  模拟器的属性,不是真实授权。

## 背景(面向人类)

身份与访问管理是每一项云安全控制的基石。反复出现的失败模式包括:权
限过度宽松的 policy(`*:*`)、把长期 access key 提交到 git、特权账
户上缺失 MFA、以及没有 `ExternalId` 的 `AssumeRole` trust policy。
Capital One(2019)、Verkada(2021)和 Uber(2022)等事故记录中根因
都是这些。

杠杆最大的控制是:

1. **优先 workload identity 而非 access key。** EKS 中通过 IRSA 假
   冒 role 的 pod,根本不需要会泄漏的凭据。
2. **每个人都启用 MFA,policy 强制。** 单一密码泄漏不足以行动。
3. **PR 时审查最小权限授予。** 限制某个权限最便宜的时机就是它被加
   入的时刻 —— 不是六个月后审计师来问的时候。
4. **强制密钥轮换。** 静态凭据会悄悄变成历史负债;把轮换自动化,免
   得被跳过。
5. **带 ExternalId 的跨账户 trust。** ExternalId 约定就能完全缓解
   Confused Deputy 这一类攻击。

当 AI 助手生成 IAM policy、trust 文档或 CI/CD 身份时,这个 skill
就是用来强制这些控制的。

## 参考

- `rules/iam_policy_invariants.json`
- `rules/key_rotation_policy.json`
- [AWS IAM Best Practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).
- [Google Cloud IAM recommender](https://cloud.google.com/iam/docs/recommender-overview).
- [NIST SP 800-53 Rev. 5](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-53r5.pdf).
- [CIS Controls v8](https://www.cisecurity.org/controls/v8).
- [CNCF Kubernetes RBAC Good Practices](https://kubernetes.io/docs/concepts/security/rbac-good-practices/).
