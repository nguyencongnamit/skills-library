---
id: saas-security
language: zh-Hans
source_revision: "f231fd47"
version: "1.0.0"
title: "SaaS 应用安全"
description: "为主流 SaaS 平台(GWS、Atlassian、Notion、HubSpot、Salesforce、BambooHR、Workday、Odoo、聊天平台、Zoom、Calendly、NetSuite)检测 token、错误配置与 admin 红旗"
category: prevention
severity: critical
applies_to:
  - "把 SaaS 的 API key 或 OAuth token 接入代码时"
  - "review SaaS connector / webhook / SCIM bridge 时"
  - "对可疑的 SaaS admin 活动做 triage 时"
  - "编写代理 SaaS 流量的基础设施时"
  - "回答与 SaaS 相关的安全问题时"
languages: ["*"]
token_budget:
  minimal: 1800
  compact: 2500
  full: 3000
rules_path: "rules/"
related_skills: ["secret-detection", "iam-best-practices", "auth-security", "supply-chain-security"]
last_updated: "2026-05-14"
sources:
  - "Google Workspace Admin SDK security guidance"
  - "Atlassian Cloud Security Best Practices"
  - "Salesforce Security Implementation Guide"
  - "HubSpot Private App authentication docs"
  - "Slack OAuth & token type reference"
  - "Microsoft Teams app permission model"
  - "Zoom App Marketplace security review"
  - "BambooHR API & Single Sign-On hardening"
  - "Workday Integration System Security framework"
  - "NetSuite Token-Based Authentication (TBA) guide"
  - "Notion API integration token model"
  - "Lark/Feishu Open Platform security guidelines"
  - "Calendly Webhook V2 signature spec"
  - "CWE-798: Use of Hard-coded Credentials"
  - "CWE-284: Improper Access Control"
  - "CWE-1392: Use of Default Credentials"
---

# SaaS 应用安全

## 规则(面向 AI 代理)

### 必须
- 把 SaaS API token、OAuth secret、webhook signing key 和
  service-account JSON 文件放进 **secrets manager**(Vault、AWS
  Secrets Manager、GCP Secret Manager、Doppler、1Password Connect)
  —— 不要写死在源码里,不要 `os.Setenv`-from-source,也不要放在 CI
  仓库变量里(只能用 `secrets.*`)。
- 对**基于 OAuth** 的 SaaS 集成(Google Workspace、Microsoft 365、
  Slack、Atlassian Cloud、HubSpot、Zoom、Notion、Lark、Calendly、
  NetSuite OAuth 2.0、Salesforce Connected Apps):把 `refresh_token`
  以加密静态保存,在过期前刷新 access token,client secret 放在
  server-only 路径里(绝不要放进 JS/mobile bundle)。
- 对 **HMAC webhook 回调**(Slack `X-Slack-Signature`、Calendly V2
  `Calendly-Webhook-Signature`、HubSpot v3
  `X-HubSpot-Signature-v3`、Stripe 风格平台、Zoom verification
  token、Teams outgoing webhook HMAC、Lark `X-Lark-Signature`、
  Notion verification token):对每一个入站请求,先校验签名和时间
  戳窗口(默认 5 分钟),**然后再**解析 body 或信任任何字段。
- 把 SaaS API 的 base URL pin 到 vendor 的生产 hostname
  (`api.atlassian.com`、`api.hubapi.com`、`api.calendly.com`、
  `*.zoom.us`、`slack.com/api`、`graph.microsoft.com`、
  `api.bamboohr.com`、`wd*.myworkday.com`、
  `*.salesforce.com`/`*.force.com`、`api.notion.com`、
  `open.larksuite.com`/`open.feishu.cn`、`*.netsuite.com`)。拒绝
  来自非预期 hostname 的响应 —— 这能挡掉 DNS-takeover 和
  account-takeover 代理这两类企图。
- 把 **SCIM** 和 **directory-sync** endpoint 当作 security-sensitive:
  要求 mutual TLS 或签名的 JWT bearer,做 rate-limit,并把每一次
  user/group write 记录到防篡改的 sink。
- 在你创建的每个 SaaS app 上使用**最小权限 scope**。Salesforce
  Connected Apps:除非必要,不要选 `full`/`refresh_token`。Slack
  bot token:只列出你实际调用的 scope。Google Workspace OAuth:
  如果不写,就申请 `.../auth/admin.directory.user.readonly`,而不
  是 `admin.directory.user`。HubSpot Private Apps:只勾选你实际
  调用的 scope checkbox。
- 在每一个 SaaS admin 控制台上强制启用**两步验证(2SV / MFA)**,
  **包括** super-admin / org-owner / billing-owner 账号。把 SSO 绑
  到你的 IdP,并禁用 admin 的 password fallback。
- 系统对系统的 SaaS 集成,要使用**专用、不共享的 service
  account**。service account 名字要能编码用途
  (`jira-ingestion-sa`,不是 `api-user-3`)。在平台允许的地方,关
  闭这些账号的交互式登录。
- 对 Google Workspace 特别注意:domain-wide delegation 的
  service-account key ≤ 90 天轮换一次,在被支持的地方优先用
  Workload Identity Federation,并在 Admin Console > Reports 里审
  计 `Admin SDK` 调用。
- 对 Atlassian (Jira/Confluence) 特别注意:优先用 **OAuth 2.0 (3LO)
  / Atlassian Connect** 配 `actAsAccountId`;只在写个人自动化脚本
  时才退回 user-bound API token。per-user API token ≤ 90 天轮换。
- 对 NetSuite 特别注意:优先 **OAuth 2.0** 或 **TBA (Token-Based
  Authentication)**,搭配专用 integration record;系统集成绝不要
  用 user/password 登录流。
- 对 BambooHR / Workday / NetSuite(HRIS/ERP 这一类):把每一次员
  工/PII 批量导出当作一个 **DLP 边界** —— 记录请求、已认证的
  principal、行数和目的地。对异常体量发告警。

### 禁止
- 不要在源码、容器镜像、移动 app 二进制或客户端 JS 里硬编码 SaaS
  API token、OAuth client secret、webhook signing key 或
  service-account JSON。本 rule 文件检测的 vendor token 格式(例如
  `xoxb-`、`xapp-`、`jira_pat_`、`pat-na`、`ya29.`、`1//`、
  `sk_live_`)在 push 后几分钟内就会被攻击者在公开 GitHub、npm、
  PyPI 和 Docker Hub 上扫描。
- 不要"为了测试"关掉 webhook 签名校验。公开记录里每一起通过伪造
  webhook 入侵 Slack / HubSpot / Zoom / Calendly / Teams / Lark /
  Notion 的事件,被利用的都是带着关闭的签名 check 上线到生产的集
  成。
- 不要把 Google Workspace 的 **super admin** OAuth scope
  (`https://www.googleapis.com/auth/admin`)给除了"IT 严格管控的
  自动化"以外的任何东西。大多数用例只需要更窄的
  `admin.directory.*.readonly`。
- 不要让 Jira、Confluence、BambooHR、Workday、NetSuite 或 Notion
  在多个服务之间共用同一个**个人 API token**。person-bound token
  继承了那个人的权限,也会从那个人的笔记本 / SaaS 账号那里漏出
  去。
- 不要让 Slack / Teams / Lark / Google Chat 的**incoming webhook
  URL** 往一个比它的调用方信任级别更高的 channel 发消息。如果
  CI bot 能往 `#secops` 发,那么 CI 一旦被攻破 = 直接对 secops 钓
  鱼。改用签名的 app + 按 channel 的 posting 权限。
- 不要把 Google Drive / Notion / Confluence / Atlassian Cloud /
  SharePoint 上含有客户数据、secret 或未公开 roadmap 的文档,**链
  接分享**设成"Anyone with the link"。把组织默认的 sharing policy
  设为 **domain-restricted**。
- 不要把 Calendly / HubSpot / Zoom 的 webhook payload 里的
  **`From` / `email` 字段**当作权威身份。签名只能证明*vendor* 发出
  了这个 payload;body 里的字段仍然可能是攻击者控制的(伪造的
  invitee、攻击者设置的 custom field)。要在 server 端按规范 ID 查
  用户。
- 不要在 dev↔staging↔prod 之间互相转发 SaaS 的 **OAuth refresh
  token** —— 每个环境必须有自己独立的 connected app / OAuth
  client,否则生产凭据就活在 dev 的爆炸半径里。
- 不要在没有 security review 的情况下信任由第三方安装的
  **Salesforce Apex / NetSuite SuiteScript / Workday Studio /
  Jira ScriptRunner** 代码。它们以高权限运行,是 SaaS 供应链事故
  的反复出现的载体(例如 Salesforce Security 2024 记录过的
  Salesforce-via-AppExchange ATO 模式)。

### 已知误报
- vendor 在官方文档里给的 **sandbox / 示例 token**(例如 Slack
  `xoxb-XXXXXXX-XXXXXXXX`、Stripe `sk_test_…`、Calendly
  `eyJ…example…`)—— 它们能匹配 regex,但周围上下文里有字面的
  `EXAMPLE` / `XXX` / `test`。
- 在第三方 SaaS 文档里讲怎么接入 GitHub 时出现的 `ghp_…` /
  `gho_…` —— 那是 GitHub token,不是 SaaS-platform 的 token,会被
  `secret-detection` 覆盖。
- 已发布的 Google Marketplace app 的 **公开 service-account
  email**(`*@gserviceaccount.com`)—— email 本来就是公开的;只有
  JSON key 才是敏感的。
- 公开 mobile / web SPA 的 **OAuth client ID** —— 它们就是设计成公
  开的。对应的 **client secret** 仍然必须保密;只对 secret 报警。

## 背景(面向人类)

SaaS 现在已经是占主导地位的数据外泄(data-egress)载体。
2023–2025 的事件记录(Snowflake / OAuth token 失窃、Okta /
HAR 文件泄露、GitHub-到-Slack 的 token replay、Salesforce-经-
Atlassian 横向移动、用 Calendly 式链接做日程/排程钓鱼)展示了
三种反复出现的失败模式:

1. **Token 散落。** 个人绑定的 token 和 OAuth refresh token 会在
   不同 vendor 之间堆积。每一个都是凭据。把它们集中起来;按节
   奏让它们过期。
2. **错误配置的分享。** SaaS 平台默认偏向方便("anyone with the
   link")。客户数据、deal pipeline、M&A 文档和内部 IAM 图,经
   由这些默认值漏出来的频率比代码 bug 还要高。
3. **Admin 行为盲区。** Bulk export、批量授权、API-key 轮换、
   SCIM user-write 异常激增,都是 account-takeover 或内部人滥用
   的诊断信号 —— 但前提是你在看。

这个 skill 的按平台 JSON rule 文件给 AI reviewer 提供:

- **Token 格式** —— 在 PR 时检测硬编码 SaaS secret 的 regex
  pattern。
- **错误配置** —— 在生成 SaaS 集成代码时要 assert(或拒绝)的
  具体配置项。
- **Admin 红旗** —— SIEM / SOAR / detection rule 早该在找的 log
  query 形状。

这些 rule 文件刻意做成 vendor-specific,这样 AI 代理就不会生成
那种会漏掉真实攻击的"通用"SaaS 检测逻辑。它们也足够小,可以让
编译出的 `SECURITY-SKILLS.md` 在 `full` 档位里把它们都带上而不
撑爆 token 预算。

## 参考

- `rules/google_workspace.json` —— GWS OAuth、service-account、Admin SDK
- `rules/google_chat.json` —— Google Chat webhook 和 bot token
- `rules/atlassian.json` —— Jira & Confluence Cloud,OAuth 2.0 / API token
- `rules/notion.json` —— Notion 集成 token,workspace 分享
- `rules/hubspot.json` —— HubSpot Private Apps、OAuth、webhook v3 HMAC
- `rules/salesforce.json` —— Connected Apps、session token、Apex/Flow
- `rules/bamboohr.json` —— BambooHR API key、SSO、员工导出
- `rules/workday.json` —— Workday ISU、OAuth、report-as-a-service
- `rules/odoo.json` —— Odoo XML-RPC / JSON-RPC、master password
- `rules/microsoft_teams.json` —— Teams app + bot 凭据、outgoing webhook HMAC
- `rules/slack.json` —— Slack bot/user/app/config token、webhook URL
- `rules/larksuite.json` —— Lark/Feishu tenant access token、webhook
- `rules/zoom.json` —— Zoom JWT (legacy)、Server-to-Server OAuth、webhook
- `rules/calendly.json` —— Calendly PAT、OAuth、V2 webhook 签名
- `rules/netsuite.json` —— NetSuite TBA、OAuth 2.0、SuiteScript 红旗
- CWE-798、CWE-284、CWE-1392
- OWASP API Security Top 10 (2023) —— API2 (auth)、API8 (security misconfig)
