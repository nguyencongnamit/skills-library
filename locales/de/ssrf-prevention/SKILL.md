---
id: ssrf-prevention
language: de
source_revision: "4c215e6f"
version: "1.0.0"
title: "SSRF-Prävention"
description: "Verteidigung gegen Server-Side Request Forgery: Cloud-Metadata-Blocking, interne IP-Filterung, DNS-Rebinding-Abwehr, allowlist-basiertes URL-Fetching"
category: prevention
severity: critical
applies_to:
  - "beim Generieren von Code, der eine vom Client gelieferte URL fetcht"
  - "beim Verdrahten von Webhooks, Image-Proxies, PDF-Renderern, oEmbed-Fetchern"
  - "beim Betrieb in einer Cloud-Umgebung mit Instance-Metadata-Service"
  - "beim Review eines URL-Parsing- oder HTTP-Client-Wrappers"
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

# SSRF-Prävention

## Regeln (für KI-Agenten)

### IMMER
- **Jede** URL, die im Auftrag eines Clients gefetcht wird, über eine
  **Allowlist** erwarteter Hosts validieren. Die Allowlist ist die
  einzige nachhaltige Verteidigung — Blocklists sind durch Encoding-
  Tricks, IPv6-Dual-Stack und DNS-Rebinding umgehbar.
- Den Hostname **einmal** auflösen, die aufgelöste IP gegen deine
  Blocklist privater / reservierter / Link-Local-Bereiche
  validieren, dann zu dieser gepinnten IP per SNI verbinden. Sonst
  kann ein Angreifer ein DNS-Rebind zwischen Validierung und
  Connect rennen (`time-of-check / time-of-use`).
- Auf Netzwerk-Layer **und** Application-Layer blockieren. Egress
  zu `169.254.169.254`, `[fd00:ec2::254]`,
  `metadata.google.internal` und `100.100.100.200` von jedem
  Service droppen, der den Metadata-Service nicht legitim braucht.
- **IMDSv2** auf AWS EC2 erzwingen (Session-Token, Hop-Limit=1).
  IMDSv1 — das Pattern, das der Capital-One-Breach 2019 ausnutzte —
  muss auf Instance-Ebene deaktiviert sein.
- HTTP-Redirects auf Server-Side-Fetchern per Default deaktivieren
  (oder nur eine kleine bounded Anzahl folgen, die neue URL bei
  jedem Hop gegen die Allowlist re-validieren). Der häufigste
  SSRF-Bypass ist `https://allowed.example.com`, der einen 302 auf
  `http://169.254.169.254/...` zurückgibt.
- Einen separaten, restriktiven HTTP-Client für *vom Benutzer
  kontrollierte* URLs vs *interne* URLs verwenden. Falsche
  Client-Nutzung muss fail-closed (z. B. via Typsystem-Distinktion
  in Go / Rust / TypeScript).
- URLs mit einem einzigen, bekannten Parser parsen (Go
  `net/url.Parse`, Python `urllib.parse`, JavaScript `new URL()`).
  Differential-Parser zwischen z. B. WHATWG und RFC-3986 sind eine
  dokumentierte SSRF-Bypass-Klasse.

### NIE
- Einem vom Benutzer gelieferten Hostname / IP vertrauen. Immer in
  deinem vertrauten Resolver re-resolven und die aufgelöste
  Adresse re-checken.
- Zu einer URL anhand ihres Hostname verbinden, wenn das Protokoll
  Redirects erlaubt — `gopher://`, `dict://`, `file://`, `jar://`,
  `netdoc://`, `ldap://` sind alle gängige SSRF-Verstärker. Auf
  `http://` und `https://` beschränken (und `ftp://` nur, wenn es
  wirklich gebraucht wird).
- `0.0.0.0`, `127.0.0.1`, `[::]`, `[::1]`, `localhost` oder
  `*.localhost.test` vertrauen — alle erreichen die lokale
  Instance. Die Liste muss auch Link-Local `169.254.0.0/16`,
  IPv4-mapped IPv6 `::ffff:127.0.0.1` und IPv6 ULA `fc00::/7`
  enthalten.
- Den URL-String des Benutzers in einer Log-Zeile oder Error-
  Response verwenden — er kann das SSRF-Reflexions-Orakel sein,
  das Blind-SSRF in Daten-Exfiltrations-SSRF verwandelt.
- Einen Metadata-Blocking-Sidecar / -Proxy als **einzige**
  Verteidigung betreiben — ein Angreifer, der einen
  Unix-Domain-Socket-Pseudo-URL oder einen fehlkonfigurierten
  Hostname findet, kann den Proxy umgehen. Application-Level-
  Allowlist bleibt erforderlich.
- IDN / Punycode in User-URLs ohne Normalisierung erlauben — IDN-
  Homograph-Angriffe umgehen naive String-Allowlist-Checks
  (`gооgle.com` mit kyrillischem o ≠ `google.com`).

### BEKANNTE FALSCH-POSITIVE
- Server-zu-Server-Integrationen, bei denen beide Seiten
  operator-kontrolliert sind und die URL im Config hartcodiert
  ist (nicht user-supplied) — die Allowlist ist hier das statische
  Config selbst.
- Cluster-lokale Kubernetes-Service-zu-Service-Calls — diese gehen
  nicht durch User-Input, aber auf etwaige Cross-Namespace-
  Network-Policy achten.
- Ausgehende Webhooks **an** den Kunden (z. B. Slack-, Discord-,
  Microsoft-Teams-Webhooks). Validieren, dass der URL-Host in der
  dokumentierten Allowlist der Integration steht, nicht beliebig.

## Kontext (für Menschen)

SSRF ist mittlerweile der De-facto-Initial-Access-Vektor für
Cloud-Breaches. Die Kette ist: eine vom Benutzer gelieferte URL →
der Server fetcht sie → der Server hat implizite Credentials
(Cloud-Metadata-IAM, interne Admin-APIs, RPC-Endpoints) → der
Angreifer stiehlt die Credentials. Der Capital-One-Breach 2019
(80M Kundendatensätze) war eine lehrbuchhafte SSRF- + IMDSv1-
Exfiltration. Die Fixes sind einfach und gut dokumentiert; die
Patterns tauchen wieder auf, weil URL-Fetching eine kleine Ecke
der meisten Codebases ist.

Dieser Skill betont die DNS-Rebinding- und Redirect-Bypass-Klassen,
weil dort von KI generierte URL-Validatoren am häufigsten
scheitern — das offensichtliche Blocken von 169.254.169.254 ist
leicht hinzuzufügen, aber das Allow-only-after-resolve-and-pin-
Pattern erfordert mehr Überlegung.

## Referenzen

- `rules/ssrf_sinks.json`
- `rules/cloud_metadata_endpoints.json`
- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html).
- [CWE-918](https://cwe.mitre.org/data/definitions/918.html).
- [Capital One 2019 breach DOJ filing](https://www.justice.gov/usao-wdwa/press-release/file/1188626/download).
- [AWS IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html).
- [PortSwigger SSRF](https://portswigger.net/web-security/ssrf).
