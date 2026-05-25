---
id: frontend-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Frontend-Sicherheit"
description: "Browserseitige Härtung: XSS, CSP, CORS, SRI, DOM-Clobbering, iframe-Sandboxing, Trusted Types"
category: prevention
severity: high
applies_to:
  - "beim Erzeugen von HTML- / JSX- / Vue- / Svelte-Templates"
  - "beim Verdrahten von Response-Headern in einer Web-App"
  - "beim Hinzufügen von Drittanbieter-Script-Tags oder CDN-Ressourcen"
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

# Frontend-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Alle User- / URL- / Storage-Daten als nicht vertrauenswürdig
  behandeln. Über Framework-Escaping rendern (`{}` in JSX/Vue/Svelte,
  `{{ }}` in Templating). Für rohes HTML einen geprüften Sanitizer
  (DOMPurify) mit strikter Allowlist verwenden.
- Einen strikten `Content-Security-Policy`-Header senden.
  Produktions-Minimum: `default-src 'self'; script-src 'self'
  'nonce-<random>'; object-src 'none'; base-uri 'self';
  frame-ancestors 'none'; form-action 'self';
  upgrade-insecure-requests`. Nonces oder Hashes verwenden — nie
  `'unsafe-inline'` für `script-src`.
- `Strict-Transport-Security: max-age=63072000; includeSubDomains;
  preload`, `X-Content-Type-Options: nosniff`,
  `Referrer-Policy: no-referrer-when-downgrade` oder strikter und
  `Permissions-Policy` setzen, um nicht genutzte Features
  abzuschalten.
- Bei jedem `<script>` und `<link rel="stylesheet">`, das von einem
  CDN geladen wird, `integrity="sha384-..." crossorigin="anonymous"`
  hinzufügen.
- Bei jedem `<iframe>` `sandbox="allow-scripts allow-same-origin"`
  hinzufügen (nur die benötigten Attribute). Standard: keine
  Allow-Flags.
- Cookies mit `Secure; HttpOnly; SameSite=Lax` (oder `Strict` für
  sensible Flows) verwenden. `__Host-`-Präfix, wenn kein
  Subdomain-Sharing genutzt wird.
- Trusted Types aktivieren, wo der Browser es unterstützt
  (`Content-Security-Policy: require-trusted-types-for 'script'`),
  damit Zuweisungen an DOM-Sinks (`innerHTML`,
  `setAttribute('src', ...)` für Scripts) durch eine getypte Policy
  laufen müssen.

### NIE
- `dangerouslySetInnerHTML`, `v-html`, `{@html ...}`,
  `innerHTML =` oder `document.write` mit nicht vertrauenswürdigem
  Input verwenden.
- `eval`, `new Function`, `setTimeout(string)`,
  `setInterval(string)` oder `Function('return x')` verwenden.
- User-Input in `href`, `src`, `formaction`, `action` oder ein
  beliebiges URL-tragendes Attribut ohne Schema-Validierung
  injizieren (`javascript:`, `data:`, `vbscript:` blockieren).
- `target="_blank"` ohne `rel="noopener noreferrer"` verwenden —
  leakt `window.opener`.
- DOM-Knoten allein anhand ihrer Id vertrauen. DOM-Clobbering: ein
  angreiferkontrolliertes `<input name="config">` überschattet
  `window.config`.
- `postMessage` ohne Prüfung von `event.origin` gegen eine
  Allowlist verwenden.
- JWTs, Refresh-Tokens oder PII in `localStorage` /
  `sessionStorage` ablegen — jedes XSS exfiltriert sie. HttpOnly-
  Cookies bevorzugen.
- `document.cookie` aus JavaScript für Auth-Cookies lesen oder
  schreiben — die sollten ohnehin HttpOnly sein.

### BEKANNTE FALSCH-POSITIVE
- Interne Admin-Tools, die bewusst Markdown / Rich Text von
  vertrauenswürdigen Autoren rendern, dürfen
  `dangerouslySetInnerHTML` nach einem Sanitizer-Durchgang
  verwenden; den Sanitizer-Aufruf inline dokumentieren.
- Browser-Extensions brauchen manchmal `'unsafe-eval'` in der
  Extension-CSP; die CSP der nach aussen gerichteten Web-App muss
  es weiterhin verbieten.
- WebSocket-Verbindungen zu nicht-same-origin Endpunkten sind in
  Ordnung, wenn der Server eine Origin-Validierung durchführt.

## Kontext (für Menschen)

Das OWASP XSS Prevention Cheat Sheet ist weiterhin die massgebliche
Referenz für die Escaping-Regeln; CSP ist die Defense-in-Depth-
Schicht, die ein vergessenes Escape in einen geloggten Report
verwandelt statt in eine gestohlene Session. Trusted Types ist das
neuere, vom Browser durchgesetzte Pattern, das die Frage "ging das
durch einen Sanitizer?" vom Laufzeit-Audit ins Typsystem schiebt.

KI-generierte Frontends greifen oft zu `innerHTML` und
`dangerouslySetInnerHTML`, weil sie kürzer sind; dieser Skill ist
das Gegengewicht.

## Referenzen

- `rules/csp_defaults.json`
- `rules/xss_sinks.json`
- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).
- [OWASP CSP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html).
- [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Cross-Site-Scripting.
- [Trusted Types (MDN)](https://developer.mozilla.org/en-US/docs/Web/API/Trusted_Types_API).
