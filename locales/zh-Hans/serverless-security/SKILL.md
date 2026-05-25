---
id: serverless-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "Serverless 安全"
description: "Lambda / Cloud Functions / Azure Functions 加固:IAM、超时、secret、event injection"
category: hardening
severity: high
applies_to:
  - "生成 AWS Lambda / GCP Cloud Functions / Azure Functions 代码时"
  - "生成 serverless.yml / SAM 模板 / functions framework 时"
  - "接入 API Gateway、EventBridge、SQS、S3 trigger 时"
languages: ["python", "javascript", "typescript", "go", "java", "yaml"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2200
rules_path: "checklists/"
related_skills: ["iac-security", "api-security", "secret-detection"]
last_updated: "2026-05-13"
sources:
  - "OWASP Serverless Top 10"
  - "AWS Well-Architected: Security Pillar — Lambda"
  - "CIS AWS Foundations Benchmark §3 (Lambda)"
  - "NIST SP 800-204 (Microservices)"
---

# Serverless 安全

## 规则(面向 AI 代理)

### 必须
- 给每个 function 各自专属的 IAM execution role,只赋所需的最小
  权限。绝不要跨 function 共享 role;绝不要复用 bootstrap / 开发
  者用的 role。
- 给 function 设具体的 timeout(同步 API ≤ 30s,后台任务 ≤
  15min)。6s 或 900s 这种默认值是两个方向上的 footgun。
- 给每个 function 设 reserved 或 provisioned concurrency 上限,
  既避免 bill blow-out,又避免一个噪音 tenant 把整个账号其他
  function 都饿死。
- cold-start 时从 secret manager(AWS Secrets Manager / GCP
  Secret Manager / Azure Key Vault)拉 secret,**带 cache**,
  不要从明文 environment variable 拿。
- 任何接触 event 的代码运行之前,先按 schema 校验 event payload。
  Lambda 不在乎 event 是从"你"的 SQS queue 来的 —— 它完全可能
  是一条 poison message。
- 启用会 redact 已知 secret pattern 的结构化日志(委托给
  `logging-security` skill)。
- 启用 X-Ray / OpenTelemetry tracing,以及对错误率、throttle
  数、p95 时延的 CloudWatch / Cloud Monitoring 告警。
- 对接私有数据库或服务的 function 应放进 VPC;否则该 function
  默认拥有完整出网,这通常不是想要的。

### 禁止
- 不要在 function role 上使用 `arn:aws:iam::*:role/*`(wildcard
  PassRole)、`*:*` action/resource 或 `iam:*` 权限。
- 不要把 secret 用明文塞进 environment variable(用 Secrets
  Manager 引用 / `aws_lambda_function.environment` 配
  `kms_key_arn`)。
- 不要把用户控制的字符串传给 `exec`、`os.system`、
  `child_process`、`subprocess.Popen(shell=True)` —— 一旦有人
  shell 出去,function URL 就成 RCE 的捷径。
- 不要把 Lambda function URL 或 API Gateway resource 本身当作
  认证。`AUTH_TYPE=NONE` 的 function URL 是无认证的;请要求
  IAM、Cognito 或 Lambda authorizer。
- 不要为生产 function 禁用
  `aws_lambda_function.code_signing_config_arn`;在 deploy 时
  签名并校验。
- 不要给容器镜像 function 用 `latest` 镜像 tag;按 digest 钉死。
- 不要在 Lambda 里用长期静态 AWS access key 来调 AWS —— 用
  execution role。
- 不要跳过对 S3 / SQS / EventBridge event payload 的校验 —— 即
  使 trigger 是"可信"的,也要假设任何 caller 都能 post 任何
  形状的数据进来。

### 已知误报
- 自定义 CloudFormation / Lambda 资源 handler(`cfn-response`)
  有时为了短期 setup 合理需要较宽权限。
- 用 CloudWatch Events 定时 ping function 来减缓 cold start 这
  类 warmer 技巧本身不是安全问题。
- 有几千个 map state 的 Step Functions 迭代器,如果
  StateMachine 本身有 concurrency cap,就不算"未追踪
  concurrency"问题。

## 背景(面向人类)

OWASP 的 Serverless Top 10 跟普通 Top 10 是同样这几大类,加上
两个 serverless 特有的:**event injection**(event 自身就携带
不可信输入 —— 一条 SQS 消息、一个 S3 object key —— 而下游代
码却把它当作可信)和 **denial-of-wallet**(攻击者耗尽你的
concurrency 来把你的账单刷爆)。

AI 助手倾向于生成 `*:*` IAM、environment variable 里放
secret、且不做 event 校验的 Lambda。本 skill 就是来对冲。

## 参考

- `checklists/lambda_hardening.yaml`
- `checklists/event_validation.yaml`
- [OWASP Serverless Top 10](https://owasp.org/www-project-serverless-top-10/).
- [AWS Well-Architected Security Pillar — Serverless](https://docs.aws.amazon.com/wellarchitected/latest/serverless-applications-lens/security-pillar.html).
