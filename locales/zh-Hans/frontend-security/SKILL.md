---
id: frontend-security
language: zh-Hans
source_revision: "afe376a8"
version: "1.0.0"
title: "前端安全"
description: "浏览器侧加固:XSS、CSP、CORS、SRI、DOM clobbering、iframe 沙箱、Trusted Types"
category: prevention
severity: high
applies_to:
  - "在生成 HTML / JSX / Vue / Svelte 模板时"
  - "在 web 应用中接入响应头时"
  - "在添加第三方 script 标签或 CDN 资源时"
languages: ["html", "javascript", "typescript", "tsx", "jsx", "vue", "svelte"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2800
rules_path: "rules/"
related_skills: ["cors-security", "auth-security", "logging-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP XSS Prevention Cheat Sheet"
  - "OWASP Content Security Policy Cheat Sheet"
  - "CWE-79: Improper Neutralization of Input During Web Page Generation"
  - "MDN Trusted Types"
---

# 前端安全

## 规则（面向 AI 代理）

### 必须
- 把所有用户/URL/storage 数据当作不可信。通过框架转义渲染
  (JSX/Vue/Svelte 用 `{}`,模板用 `{{ }}`)。原始 HTML 用经过审计的
  sanitizer(DOMPurify)配合严格 allowlist。
- 发送严格的 `Content-Security-Policy` 头。生产最低基线:
  `default-src 'self'; script-src 'self' 'nonce-<random>'; object-src
  'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self';
  upgrade-insecure-requests`。使用 nonce 或 hash —— 永远不要在
  `script-src` 里用 `'unsafe-inline'`。
- 设置 `Strict-Transport-Security: max-age=63072000; includeSubDomains;
  preload`、`X-Content-Type-Options: nosniff`、
  `Referrer-Policy: no-referrer-when-downgrade` 或更严,以及
  `Permissions-Policy` 来禁用未使用的特性。
- 给从 CDN 加载的每个 `<script>` 和 `<link rel="stylesheet">` 加
  `integrity="sha384-..." crossorigin="anonymous"`。
- 给每个 `<iframe>` 加 `sandbox="allow-scripts allow-same-origin"`
  (只加需要的属性)。默认不加任何 allow 标志。
- 使用带 `Secure; HttpOnly; SameSite=Lax`(敏感流程用 `Strict`)的
  cookie。无子域共享时使用 `__Host-` 前缀。
- 在浏览器支持时启用 Trusted Types
  (`Content-Security-Policy: require-trusted-types-for 'script'`),
  让 DOM sink 赋值(`innerHTML`、给 script 用的
  `setAttribute('src', ...)`)必须经过类型化的 policy。

### 禁止
- 不要把不可信输入交给 `dangerouslySetInnerHTML`、`v-html`、
  `{@html ...}`、`innerHTML =` 或 `document.write`。
- 不要使用 `eval`、`new Function`、`setTimeout(string)`、
  `setInterval(string)` 或 `Function('return x')`。
- 不要把用户输入未经 scheme 校验地注入到 `href`、`src`、
  `formaction`、`action` 或任何携带 URL 的属性(阻断 `javascript:`、
  `data:`、`vbscript:`)。
- 不要在没有 `rel="noopener noreferrer"` 的情况下使用
  `target="_blank"` —— 会泄漏 `window.opener`。
- 不要仅凭 id 信任 DOM 节点。DOM clobbering:攻击者控制的
  `<input name="config">` 会遮蔽 `window.config`。
- 不要在使用 `postMessage` 时不对 `event.origin` 做 allowlist 校验。
- 不要把 JWT、refresh token 或 PII 存到 `localStorage` /
  `sessionStorage` —— 任意 XSS 都能外泄。优先使用 HttpOnly cookie。
- 不要在 JavaScript 里读写认证用 cookie 的 `document.cookie` —— 它们
  本就应该是 HttpOnly。

### 已知误报
- 内部管理工具刻意渲染来自可信作者的 Markdown / 富文本时,可以在过了
  sanitizer 之后使用 `dangerouslySetInnerHTML`;在 inline 注释中写明
  sanitizer 调用。
- 浏览器扩展有时需要在扩展 CSP 里使用 `'unsafe-eval'`;面向用户的 web
  应用 CSP 仍应禁止。
- 与非 same-origin 端点的 WebSocket 连接在服务端有 origin 校验时是
  可以接受的。

## 背景(面向人类)

OWASP XSS Prevention Cheat Sheet 至今仍是转义规则的权威参考;CSP 是
纵深防御层,让一次漏掉的转义变成一条记录上报,而不是一个被偷的会话。
Trusted Types 是更新的、由浏览器强制的模式,把"这个有过 sanitizer
吗?"从运行时审计移交给类型系统。

AI 生成的前端常常会顺手用 `innerHTML` 和 `dangerouslySetInnerHTML`,
因为它们更短;这个 skill 就是对冲。

## 参考

- `rules/csp_defaults.json`
- `rules/xss_sinks.json`
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html) —— 跨站脚本。
- [Trusted Types (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).
