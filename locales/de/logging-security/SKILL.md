---
id: logging-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "Logging-Sicherheit"
description: "Secret-/PII-Leaks in Logs verhindern, Log-Injection-Angriffe abwehren, Audit-Trails sicherstellen, schwache Retention vermeiden"
category: prevention
severity: high
applies_to:
  - "beim Erzeugen von Logger-Calls oder Schemas für strukturiertes Logging"
  - "beim Verdrahten von Log-Shippern, Sinks, Retention und Zugriffskontrollen"
  - "beim Review von Anforderungen für Audit-Logging"
languages: ["*"]
token_budget:
  minimal: 1000
  compact: 1100
  full: 2400
rules_path: "rules/"
related_skills: ["secret-detection", "error-handling-security", "compliance-awareness"]
last_updated: "2026-05-13"
sources:
  - "OWASP Logging Cheat Sheet"
  - "CWE-532 — Insertion of Sensitive Information into Log File"
  - "CWE-117 — Improper Output Neutralization for Logs"
  - "NIST SP 800-92 (Guide to Computer Security Log Management)"
---

# Logging-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- In einem **strukturierten Format** loggen (JSON oder logfmt) mit
  stabilen Feldnamen. `timestamp`, `service`, `version`, `level`,
  `trace_id`, `span_id`, `user_id` (bei Authentifizierung),
  `request_id`, `event` einschliessen.
- Jede Log-Nachricht durch einen **Redactor** schicken, bevor sie
  den Log-Sink erreicht: Passwörter, Tokens, API-Keys, Cookies,
  vollständige URLs mit `?token=`, gängige PII-Muster (SSN-ähnlich,
  Kreditkarten-ähnlich, optional E-Mail).
- Newlines / Steuerzeichen in jedem user-kontrollierten String vor
  dem Loggen bereinigen (CWE-117): `\n`, `\r`, `\t` ersetzen, damit
  ein Angreifer keine gefälschten Log-Zeilen einschleusen kann.
- Sicherheitsrelevante Ereignisse als **unveränderliche Audit-
  Records** loggen: Login-Erfolg/-Fehlschlag, MFA-Challenges,
  Passwortwechsel, Rollenwechsel, Access Grant/Revoke, Datenexport,
  Admin-Aktion. Audit-Records bekommen längere Retention und
  strengeren Zugriff.
- Retention pro Datenkategorie setzen, nicht global: kurz für Debug,
  lang für Audit, kein PII nach Ablauf der Einwilligung.
- Logs an einen zentralen, append-only Store schicken (Cloud
  Logging, CloudWatch, Elastic, Loki) mit Lese-Zugriff beschränkt
  auf Engineering / SecOps.
- Auf fehlende Logs eines Services alarmieren (silent failure) und
  auf Log-Volumen-Anomalien (10× Spike oder 10× Abfall).

### NIE
- Vollständige Request-/Response-Bodies auf INFO loggen. Bodies
  enthalten regelmässig Passwörter, Tokens, PII und hochgeladene
  Dateien.
- `Authorization`-Header, `Cookie` / `Set-Cookie`-Header,
  Query-String-Tokens oder irgendein Feld namens `password`,
  `secret`, `token`, `key`, `private` oder `credential` loggen —
  auch nicht nach "Obfuskation" wie `***`.
- Komplette gebundene SQL-Statements mit Parameterwerten loggen;
  stattdessen das Template + Parameter-*Namen* + einen gehashten
  Wert-Identifier loggen.
- Unprivilegierten Usern erlauben, Raw-Logs mit Daten anderer User
  zu lesen.
- Plain `print()` / `console.log` / `fmt.Println` in Produktions-
  Services verwenden; den konfigurierten Logger nutzen, damit
  Redaction und Struktur einheitlich angewandt werden.
- Logging fehlgeschlagener Authentifizierungs-Versuche
  deaktivieren, um "Lärm zu reduzieren" — Brute-Force-Erkennung
  hängt von diesen Records ab.
- In Produktion in eine einzige lokale Datei loggen; diese Logs
  gehen verloren, wenn der Pod / Container / die VM stirbt.

### BEKANNTE FALSCH-POSITIVE
- Health-Check- oder Load-Balancer-Probe-Logs können legitim am
  Load Balancer heruntergesampelt / unterdrückt werden, um Volumen
  zu sparen.
- Ein `request_id`-Wert, der wie ein Token aussieht, ist kein
  Token — pattern-matchende Redactors können über-redacten;
  bekannte sichere Prefixe whitelisten (z. B. deine
  `req_`-Korrelations-IDs).
- Anonyme Public-API-Access-Logs ohne Auth-Header sind per se kein
  Privacy-Problem; Client-IPs können unter DSGVO trotzdem PII sein.

## Kontext (für Menschen)

Logs sind der häufigste Ort, an dem Secrets als Klartext landen —
Request-Dumps, Exception-Traces, Debug-Prints, Telemetry von
Drittpartei-SDKs. Das OWASP Logging Cheat Sheet deckt die
operativen Regeln ab; NIST SP 800-92 deckt die Retention-/
Zentralisierungs-/Audit-Trail-Seite ab. Die Audit-Trail-
Anforderungen tauchen in SOC 2 CC7.2, PCI-DSS 10, HIPAA
§164.312(b) und ISO 27001 A.12.4 auf.

Dieser Skill ist der Partner zu `secret-detection` (das Source
scannt) und `error-handling-security` (das die externe Response
sanitiert). Logs liegen dazwischen und bluten in beide Richtungen.

## Referenzen

- `rules/redaction_patterns.json`
- `rules/audit_event_schema.json`
- [OWASP Logging Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html).
- [CWE-532](https://cwe.mitre.org/data/definitions/532.html).
- [CWE-117](https://cwe.mitre.org/data/definitions/117.html).
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final).
