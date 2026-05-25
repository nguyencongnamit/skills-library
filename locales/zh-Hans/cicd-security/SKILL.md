---
id: cicd-security
language: zh-Hans
source_revision: "4c215e6f"
version: "1.0.0"
title: "CI/CD 流水线安全"
description: "加固 GitHub Actions、GitLab CI 及类似流水线,使其能抵御供应链攻击、密钥外泄以及 pwn-request 类滥用"
category: prevention
severity: critical
applies_to:
  - "在编写或评审 CI/CD 工作流文件时"
  - "在向流水线引入第三方 action / 镜像 / 脚本时"
  - "在把云或 registry 凭证接入 CI 时"
  - "在排查疑似流水线被攻破时"
languages: ["yaml", "shell", "*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "checklists/"
related_skills: ["supply-chain-security", "secret-detection", "container-security"]
last_updated: "2026-05-13"
sources:
  - "OpenSSF Scorecard — Pinned-Dependencies / Token-Permissions"
  - "SLSA v1.0 Build Track"
  - "GitHub Security Lab — Preventing pwn requests"
  - "StepSecurity — tj-actions/changed-files attack analysis"
  - "CWE-1395: Dependency on Vulnerable Third-Party Component"
---

# CI/CD 流水线安全

## 规则（面向 AI 代理）

### 必须
- 每个第三方 GitHub Action 都按**提交 SHA**(完整 40 位字符)固定,不要按
  tag——tag 可以被重新推送。GitLab CI 的 `include:` 引用和可复用工作流同理。
  Renovate / Dependabot 可以帮你保持 SHA 固定项保持最新。
- 在 workflow 或 job 级别声明 `permissions:`,默认仅 `contents: read`。
  额外作用域(`id-token: write`、`packages: write` 等)按 job 单独授予,
  不要全 workflow 通用。
- 使用 **OIDC** (`id-token: write` + 云厂商的信任策略) 来获取短期云凭证。
  不要把 AWS / GCP / Azure 的长期密钥存为 GitHub Secrets。
- 把 `pull_request_target`、`workflow_run` 以及任何使用了
  `actions/checkout` 并 `ref: ${{ github.event.pull_request.head.ref }}`
  的 `pull_request` job 都视为**在不可信代码上运行的可信上下文**。要么不要
  运行,要么以没有 secret、没有写权限令牌的方式运行。
- 所有不可信表达式 (`${{ github.event.* }}`) 都要先写入环境变量;
  绝不要直接插值进 `run:` 主体——这是 GitHub Actions 经典的 script-injection
  汇点。
- 给 release 工件签名(Sigstore / cosign),并发布 SLSA provenance 证明。
  任何拉取该工件的消费者流水线都应该校验 provenance。
- 把 `runs-on` 设为加固过的 runner 镜像,并固定 runner 版本。对任何处理
  secret 的工作流,建议使用 StepSecurity Harden-Runner 的 audit 模式
  (或等价的出口防火墙)。
- 把 CI 里调用的 `npm install`、`pip install`、`go install`、
  `cargo install`、`docker pull` 视为不可信代码执行。运行时加
  `--ignore-scripts` (npm/yarn)、固定 lockfile、registry allowlist,
  以及按 job 授予最小权限的 token。

### 禁止
- 用浮动 tag (`@v1`、`@main`、`@latest`) 来固定第三方 action。
  2025 年 3 月的 tj-actions/changed-files 事件正是因为使用方采用了浮动
  tag,才从 23,000+ 仓库中外泄了 secret。
- 在 CI 中 `curl | bash`(或 `wget -O- | sh`)任何安装脚本。2021 年
  Codecov 的 bash uploader 被攻破后,因为成千上万的流水线运行
  `bash <(curl https://codecov.io/bash)`,环境变量被外泄长达约 10 周。
  请先下载、校验校验和、再执行。
- 把 secret 输出到日志,即便在失败时也不行。对任何运行时计算出的 secret
  使用 `::add-mask::`,并通过 GitHub 工作流日志搜索做二次确认。
- 当某个 job 触及写权限令牌或 secret 时,使用 `pull_request_target`
  让工作流在 fork PR 上运行。这种组合就是 GitHub Security Lab 记录的
  经典 "pwn request" 模式。
- 仅用 `os` 作为缓存 key 缓存可变状态(例如 `~/.npm`、`~/.cargo`、
  `~/.gradle`)。跨 job 的缓存命中是跨租户攻击面——按 lockfile 哈希作为 key
  并限定到工作流的 ref。
- 在没有校验源工作流 + 提交 SHA 的前提下,信任来自任意工作流运行的工件
  下载。build-cache 投毒就是通过无作用域的工件复用进行的。
- 把 secret 存到仓库变量 (`vars.*`) ——任何拥有读权限的人都能看到明文。
  只有 `secrets.*` 才会被 secret scanning 与作用域规则保护。

### 已知误报
- 同一组织内你自己镜像或 fork 的 first-party action,如果组织对该 action
  仓库强制要求签名 tag + 分支保护,那么按 tag 固定是合法的。
- 不处理 secret、不产生签名工件的公开数据流水线(例如夜间链接检查),
  不需要 OIDC 或 SLSA provenance,使用浮动 tag 在实务上没有影响。
- `pull_request_target` 对只调用最小作用域 GitHub API、不 checkout PR
  代码、也不在 env 中暴露 secret 的 label / triage 机器人来说是合法的。

## 背景(面向人类)

CI/CD 现已成为供应链上回报最高的单一目标。一条流水线把可信代码运行在
可信凭证与可信 registry 上——一次攻破就能拿到它产出的每个工件的所有
下游消费者。2021 Codecov、2021 SolarWinds、2024 Ultralytics PyPI 发布
流水线投毒、以及 2025 年的 tj-actions/changed-files 大规模外泄,都依靠
对 CI 所消费的脚本或 action 的未经认证的改动。

大多数防御措施是机械化的:按 SHA 固定、最小化权限、使用 OIDC、签名
工件、校验 provenance。难的是在组织层面强制执行。OpenSSF Scorecard
为这些机械防御自动化了检查,并能与分支保护打通。

本 skill 重点强调设计模式层面的弱点(pwn requests、script injection、
curl-pipe-bash、浮动 tag、不可信工件下载),因为这些恰恰是 AI 生成的
工作流 YAML 最常重新发明的反模式。

## 参考

- `checklists/github_actions_hardening.yaml`
- `checklists/gitlab_ci_hardening.yaml`
- [OpenSSF Scorecard](https://github.com/ossf/scorecard).
- [SLSA v1.0 Build Track](https://slsa.dev/spec/v1.0/levels).
- [GitHub Security Lab — Preventing pwn requests](https://securitylab.github.com/research/github-actions-preventing-pwn-requests/).
- [StepSecurity — tj-actions/changed-files attack analysis](https://www.stepsecurity.io/blog/tj-actions-changed-files-attack-analysis).
- [CWE-1395](https://cwe.mitre.org/data/definitions/1395.html).
