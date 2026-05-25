---
id: ssrf-prevention
version: "1.0.0"
title: "SSRF Prevention"
description: "Defend against Server-Side Request Forgery: cloud metadata blocking, internal IP filtering, DNS rebinding defense, allowlist-based URL fetching"
category: prevention
severity: critical
applies_to:
  - "when generating code that fetches a URL supplied by the client"
  - "when wiring webhooks, image proxies, PDF renderers, oEmbed fetchers"
  - "when running in any cloud environment with an instance metadata service"
  - "when reviewing a URL-parsing or HTTP-client wrapper"
languages: ["*"]
token_budget:
  minimal: 1200
  compact: 1500
  full: 2200
rules_path: "rules/"
related_skills: ["api-security", "cors-security", "infrastructure-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP SSRF Prevention Cheat Sheet"
  - "CWE-918: Server-Side Request Forgery"
  - "Capital One 2019 breach post-mortem (IMDSv1 SSRF)"
  - "AWS IMDSv2 documentation"
  - "PortSwigger Web Security Academy — SSRF labs"
---

# SSRF Prevention

## Rules (for AI agents)

### ALWAYS
- Validate **every** URL fetched on behalf of a client through an **allowlist**
  of expected hosts. The allowlist is the only durable defense — block-lists
  are bypassable through encoding tricks, IPv6 dual-stack, and DNS rebinding.
- Resolve the hostname **once**, validate the resolved IP against your
  block-list of private / reserved / link-local ranges, then connect to that
  pinned IP using SNI. Otherwise an attacker can race a DNS rebind between
  validation and connect (`time-of-check / time-of-use`).
- Block at the network layer **and** at the application layer. Drop egress to
  `169.254.169.254`, `[fd00:ec2::254]`, `metadata.google.internal`, and
  `100.100.100.200` from any service that doesn't legitimately need the
  metadata service.
- Enforce **IMDSv2** on AWS EC2 (session-token, hop-limit=1). IMDSv1 — the
  pattern Capital One's 2019 breach exploited — must be disabled at the
  instance level.
- Disable HTTP redirects by default on server-side fetchers (or follow only
  a small bounded number, re-validating the new URL against the allowlist
  at each hop). The most common SSRF bypass is `https://allowed.example.com`
  returning a 302 to `http://169.254.169.254/...`.
- Use a separate, restricted HTTP client for *user-controlled* URLs vs
  *internal* URLs. Misusing the wrong client must fail closed (e.g. via
  type-system distinction in Go / Rust / TypeScript).
- Parse URLs with a single, well-known parser (Go `net/url.Parse`,
  Python `urllib.parse`, JavaScript `new URL()`). Differential parsers
  between e.g. WHATWG and RFC-3986 are a documented SSRF bypass class.

### NEVER
- Trust a hostname / IP that was supplied by the user. Always re-resolve
  in your trusted resolver and re-check the resolved address.
- Connect to a URL based on its hostname when the protocol allows
  redirects — `gopher://`, `dict://`, `file://`, `jar://`, `netdoc://`,
  `ldap://` are all common SSRF amplifiers. Restrict to `http://` and
  `https://` (and `ftp://` only if you actually need it).
- Trust `0.0.0.0`, `127.0.0.1`, `[::]`, `[::1]`, `localhost`, or
  `*.localhost.test` — all of them reach the local instance. The list also
  must include link-local `169.254.0.0/16`, IPv4-mapped IPv6
  `::ffff:127.0.0.1`, and IPv6 ULA `fc00::/7`.
- Use the user's URL string in a logging line or an error response —
  it can be the SSRF reflection oracle that turns blind SSRF into
  data-exfiltration SSRF.
- Run a metadata-blocking sidecar / proxy as the **only** defense — an
  attacker who finds a Unix-domain-socket pseudo-URL or a misconfigured
  hostname can route around the proxy. Application-level allowlist
  remains required.
- Allow IDN / Punycode in user URLs without normalization — IDN homograph
  attacks bypass naive string-allowlist checks (`gооgle.com` Cyrillic-o
  ≠ `google.com`).

### KNOWN FALSE POSITIVES
- Server-to-server integrations where both sides are operator-controlled
  and the URL is hard-coded in config (not user-supplied) — the allowlist
  here is the static config itself.
- Cluster-local Kubernetes service-to-service calls — these don't go
  through user input, but be aware of any cross-namespace network policy.
- Outbound webhooks **to** the customer (e.g. Slack, Discord, Microsoft
  Teams webhooks). Validate that the URL host is in the integration's
  documented allowlist, not arbitrary.

## Context (for humans)

SSRF is now the de-facto initial-access vector for cloud breaches. The
chain is: a user-supplied URL → the server fetches it → the server has
implicit credentials (cloud metadata IAM, internal admin APIs, RPC
endpoints) → attacker steals the credentials. Capital One's 2019 breach
(80M customer records) was a textbook SSRF + IMDSv1 exfiltration. The
fixes are simple and well-documented; the patterns reappear because
URL-fetching is a tiny corner of most codebases.

This skill emphasizes the DNS-rebinding and redirect-bypass classes
because those are where AI-generated URL validators most often fail —
the obvious 169.254.169.254 block is easy to add, but the
allow-only-after-resolve-and-pin pattern requires more thought.

## References

- `rules/ssrf_sinks.json`
- `rules/cloud_metadata_endpoints.json`
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
- [Capital One 2019 breach DOJ filing](https://www.justice.gov/usao-wdwa/press-release/file/1188626/download).
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf).
