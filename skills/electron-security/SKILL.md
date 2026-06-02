---
id: electron-security
version: "1.0.0"
title: "Electron Desktop Security"
description: "Harden Electron apps: renderer trust boundary (nodeIntegration, contextIsolation, sandbox), contextBridge/IPC allowlists, shell.openExternal, navigation guards, deep-link auth, safeStorage"
category: hardening
severity: critical
applies_to:
  - "when generating Electron main-process code (BrowserWindow, ipcMain, app events)"
  - "when generating a preload script or contextBridge surface"
  - "when wiring custom-protocol / deep-link handlers"
  - "when storing tokens or secrets in an Electron app"
  - "when reviewing Electron IPC, navigation, or window configuration"
languages: ["javascript", "typescript"]
token_budget:
  minimal: 1000
  compact: 1400
  full: 2600
rules_path: "checklists/"
related_skills: ["frontend-security", "secret-detection", "auth-security"]
last_updated: "2026-06-02"
sources:
  - "Electron Security Checklist (official docs)"
  - "OWASP — Electron / desktop application security"
  - "CWE-78, CWE-22, CWE-250, CWE-693, CWE-829, CWE-1188"
  - "Doyensec / Electronegativity research on Electron attack surface"
---

# Electron Desktop Security

## Rules (for AI agents)

The unifying principle: **treat the renderer as untrusted**. Any renderer-side
code execution (XSS in rendered content, a redirect, a deep link) must NOT be
able to reach Node, the shell, the filesystem, or session tokens. Lock the
renderer-trust boundary first; every IPC sink is reachable from a compromised
renderer.

### ALWAYS
- Configure every `BrowserWindow` with `nodeIntegration: false`,
  `contextIsolation: true`, and `sandbox: true`. The preload + contextBridge
  is the supported way to give the renderer capabilities — the page never
  needs Node.
- Expose a **minimal, typed** API from the preload via `contextBridge.exposeInMainWorld`.
  Expose named functions only — never hand the renderer `ipcRenderer`,
  `require`, `process`, or whole modules.
- Validate **every** IPC argument in the main-process handler: type-check,
  bound, and allowlist. The renderer is an attacker-controlled input source.
- Spawn child processes with `execFile` / `spawn` and an **argument array** —
  never `exec` with a shell string built from renderer input. Allowlist each
  argument (e.g. `^[A-Za-z0-9_-]+$`).
- Confine filesystem paths: `path.resolve(base, input)` then verify the result
  `startsWith(base + path.sep)`. Reject absolute paths and `..` segments.
- Allowlist `shell.openExternal` to `https:` (and `mailto:` if needed) after
  parsing the URL. Reject `file:`, custom schemes, and anything else.
- Add navigation guards: `app.on('web-contents-created', …)` with
  `contents.on('will-navigate', …)` and `contents.setWindowOpenHandler(…)`
  that **deny by default** against a strict origin allowlist.
- Before attaching session tokens / cookies to an outbound request, verify the
  target host is on your own-API allowlist. Never attach credentials to a
  renderer-supplied URL.
- Bind custom-protocol / deep-link auth to a one-time `state` / PKCE value the
  app generated and is waiting for; validate before storing any token.
- Store tokens with Electron `safeStorage` (OS keychain / DPAPI / libsecret),
  not app-level crypto. Enable ASAR integrity + code signing for release.

### NEVER
- Set `nodeIntegration: true`, disable `contextIsolation`, disable
  `webSecurity`, or set `allowRunningInsecureContent: true` — especially when
  the window loads remote or navigable content.
- Concatenate renderer input into a shell string
  (`child_process.exec(\`docker kill ${names}\`)`) — command injection.
- Concatenate a renderer-supplied path for `fs` read/write
  (`${BASE}${filePath}`) — path traversal / arbitrary file write.
- Call `shell.openExternal` on an arbitrary or renderer-controlled URL —
  `file:` / custom protocol handlers are a local-launch / RCE vector.
- Attach `Authorization` / session cookies to a URL the renderer chose without
  a host allowlist — XSS then exfiltrates the token.
- Accept a deep-link auth token (`myapp://auth?refresh-token=…`) without
  origin / `state` validation — login CSRF / session fixation.
- Encrypt tokens at rest with AES-CBC (no integrity) or a key derived solely
  from a locally recoverable machine ID, and never keep a `PLAINTEXT:`
  fallback path.

### KNOWN FALSE POSITIVES
- Dev builds that load over `http://localhost:<port>` with relaxed settings —
  the rules apply to **release** builds; ensure dev config never ships.
- A custom protocol (`myapp://`) for OAuth callbacks is expected — the control
  is `state`/PKCE validation, not the scheme's existence.
- `contextBridge`-exposed functions are intentional capabilities; review what
  each one does (and whether it validates input), not the fact that the bridge
  exists.
- `shell.openExternal` on a hard-coded `https://` constant (not user input) is
  fine.

## Context (for humans)

Electron ships a Chromium renderer and a Node main process in one app. The
single most dangerous misconfiguration is `nodeIntegration: true` with no
navigation guards: it turns any renderer-side bug (XSS in a report/telemetry
view, an open redirect, a deep link) into full host RCE. Every IPC handler the
preload exposes — file write, process exec, `openExternal`, token access — is
then reachable by attacker-controlled renderer code.

AI assistants frequently generate Electron windows with `nodeIntegration: true`
(it makes `require` "just work" in the page), `child_process.exec` with
template-string interpolation, `shell.openExternal(url)` with no validation,
and custom token crypto instead of `safeStorage`. This skill is the
counterweight: keep the renderer sandboxed and every IPC sink validated.

## References

- `checklists/electron_hardening.yaml` — machine-readable hardening checks
  (window config, IPC sinks, navigation, deep-link, token storage).
- [Electron Security Checklist](https://www.electronjs.org/docs/latest/tutorial/security).
- [CWE-78 — OS Command Injection](https://cwe.mitre.org/data/definitions/78.html).
- [CWE-22 — Path Traversal](https://cwe.mitre.org/data/definitions/22.html).
- [CWE-250 — Execution with Unnecessary Privileges](https://cwe.mitre.org/data/definitions/250.html).
