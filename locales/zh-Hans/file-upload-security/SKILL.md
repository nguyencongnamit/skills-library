---
id: file-upload-security
language: zh-Hans
source_revision: "4c215e6f"
version: "1.0.0"
title: "文件上传安全"
description: "校验用户上传:MIME magic bytes、文件名清洗、大小限制、独立服务域、AV 扫描、polyglot 检测"
category: prevention
severity: high
applies_to:
  - "在生成 HTTP 文件上传端点时"
  - "在配置通过预签名 URL 上传到 S3 / GCS / Azure Blob 时"
  - "在添加对用户上传的图像/PDF/文档处理时"
  - "在审查用户生成内容的存储与分发时"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "ssrf-prevention", "infrastructure-security", "cors-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP File Upload Cheat Sheet"
  - "CWE-434: Unrestricted Upload of File with Dangerous Type"
  - "CWE-22: Path Traversal"
  - "CVE-2018-15473 (libmagic), CVE-2016-3714 (ImageTragick)"
---

# 文件上传安全

## 规则（面向 AI 代理）

### 必须
- 在服务端校验每个上传的**magic bytes**。`Content-Type` 与文件扩展名
  都由攻击者控制,绝不可作为依据。使用 libmagic、`file-type`(Node)、
  `mimetypes-magic`(Python)或 Tika。
- 按端点维护一份允许的类型 **allowlist**(`image/png`、`image/jpeg`、
  `application/pdf`、…)。拒绝其他一切,包括 `text/html`、
  `image/svg+xml`(携带 `<script>`)、`text/xml` 和
  `application/octet-stream`。
- 清洗文件名:去掉目录组件、规范化 Unicode、拒绝 `..`、NUL 字节、控
  制字符、Windows 保留名(`CON`、`PRN`、`AUX`、`NUL`、`COM1-9`、
  `LPT1-9`)以及任何非 `[a-zA-Z0-9._-]` 的字符。以 UUID / 哈希存盘,
  并把原始文件名放在单独、转义过的 metadata 列里。
- 在 proxy / API gateway *和*应用层同时强制**大小限制** —— 至少做双
  层。proxy 限制防带宽 DoS;应用层限制在 proxy 配置错误时仍能防内
  存耗尽。
- 把上传**放在 document root 之外**,从独立域名
  (`usercontent.example.net`)的 CDN 上提供下载。对非图像类型设
  `Content-Disposition: attachment`,并加
  `Content-Security-Policy: default-src 'none'; sandbox` header,以
  抵消任何 inline 渲染的 HTML/SVG。
- 在让其他用户访问之前,用**杀毒扫描器**(ClamAV、VirusTotal、Sophos)
  扫描每一份上传 —— 异步进行,以免请求本身被延迟绑定。
- 在服务端**重新编码**媒体:`convert in.jpg out.jpg`(配合严格
  `policy.xml` 的 ImageMagick)、视频用 `ffmpeg -i`、PDF 用
  `pdftocairo`。重新编码可剥离大多数 polyglot / 隐写 payload 和奇特
  的 codec 漏洞。
- 对 SVG 特别处理:要么在服务端渲染成栅格格式,要么经过严格 allowlist
  的 sanitizer(Node 用 DOMPurify,Python 用 `lxml.html.clean`),
  剥离 `<script>`、`<iframe>`、`<foreignObject>`、带 `javascript:` 的
  `xlink:href`,以及 CSS 中的 expression / 非 data URI 的 url()。

### 禁止
- 不要相信客户端的 `Content-Type`。IE / 旧 Chrome 的 MIME 嗅探器会读
  body 找类型线索 —— 一个伪装成 `image/png` 的 HTML payload 一旦被
  same-origin 提供,就会作为 HTML 执行。
- 不要用用户提供的文件名构造存储路径。路径穿越
  (`../../etc/passwd`)和 Windows 保留名都归结为"让攻击者选择写入位
  置"。
- 不要用应用相同的 origin 提供上传内容。在 `api.example.com/uploads/x.html`
  上提供意味着一个恶意 HTML 上传可以完整访问 api.example.com 的 cookie
  和 CORS。
- 不要在没有严格 policy.xml / 沙箱 / 版本控制的情况下让 ImageMagick /
  libraw / ExifTool / ffmpeg 处理上传。ImageTragick(CVE-2016-3714)
  和 GitLab ExifTool(CVE-2021-22205)都依赖服务器轻易地把用户控制的
  字节交给媒体库。
- 不要允许上传 PDF + 浏览器内渲染而不校验 PDF 通过结构性验证(例如
  `pdfinfo`)。恶意 PDF 是针对接收端 Adobe Reader 的常见
  JavaScript-in-PDF / XFA RCE 原语,即便服务器端是安全的。
- 不要用 `unzip` 或 `python -m zipfile` 处理 `.docx` / `.xlsx` /
  `.zip` 解压而没有路径穿越安全的解压器。Zip slip
  (CVE-2018-1002201)通过 `../` 条目把文件解压到目标目录之外。
- 不要在没有严格签名的 `Content-Type` condition 和固定 object-key 前
  缀的情况下使用 S3 / GCS 预签名上传 URL。没有这些 condition,客户端
  可以把任意内容上传到任意键。

### 已知误报
- 仅限内部的 admin 上传(例如运维 dashboard)可以合法地相信文件扩展
  名,因为信任边界是 SSO + IP allowlist。在端点中把它记录为有意的决
  定。
- 一些集成(例如从 BI 工具导出 CSV)需要保留用户提供的文件名往返;在
  metadata 中保留它们,但磁盘上的名字必须仍是 UUID。
- 构建流水线里的 tarball / DEB / RPM 不需要 AV 扫描 —— 信任边界是构
  建流水线的签名密钥,而不是 AV。

## 背景(面向人类)

文件上传是一个内容丰富且持久存在的攻击面。每一个现实世界的 breach
实验都把"找到上传表单"列为早期动作,因为从上传到 RCE 的路径通常很
短:上传带 JavaScript 凭证窃取器的 HTML 文件、上传到错配 doc-root
的 PHP / JSP shell、上传带 SAML 窃取器 `<script>` 的 SVG、给易受
攻击的 ImageMagick 服务上传一张 EXIF 里带 payload 的图像。

防御方法早已成熟且代价不大 —— 问题在于必须组合使用。一个 magic-byte
allowlist 会被 polyglot(同时是合法 PNG 又是合法 HTML 页面的文件)
轻易绕过。独立的服务域名抵消 polyglot 的 HTML 执行。杀毒扫描抓已知
恶意软件。重新编码剥离奇特的 codec payload。每一层都是一道防线;缺
任意一层都会让大多数上传从"存了数据"变成"存了 RCE"。

## 参考

- `rules/upload_validation.json`
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html).
- [CWE-434](https://cwe.mitre.org/data/definitions/434.html).
- [CWE-22 (Path Traversal)](https://cwe.mitre.org/data/definitions/22.html).
- [Snyk Zip Slip directory](https://snyk.io/research/zip-slip-vulnerability).
- [ImageTragick (CVE-2016-3714)](https://imagetragick.com/).
