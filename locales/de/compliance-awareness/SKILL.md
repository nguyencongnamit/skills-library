---
id: compliance-awareness
language: de
source_revision: "8e503523"
version: "1.0.0"
title: "Compliance-Bewusstsein"
description: "Generierten Code zu OWASP-, CWE- und SANS-Top-25-Kontrollen für Rückverfolgbarkeit mappen"
category: compliance
severity: medium
applies_to:
  - "beim Erzeugen von Code in regulierten Umgebungen"
  - "beim Schreiben auditrelevanter Kommentare oder Dokumentation"
  - "beim Refactoring von Code, der Compliance-Grenzen kreuzt (PII, PHI, PCI-Scope)"
languages: ["*"]
token_budget:
  minimal: 400
  compact: 700
  full: 2000
rules_path: "frameworks/"
related_skills: ["secure-code-review", "api-security"]
last_updated: "2026-05-14"
sources:
  - "OWASP Top 10 2021"
  - "CWE Top 25 2023"
  - "PCI DSS v4.0"
  - "HIPAA Security Rule"
  - "SOC 2 Trust Services Criteria"
---

# Compliance-Bewusstsein

## Regeln (für KI-Agenten)

### IMMER
- Funktionen, die PII- / PHI- / PCI-Daten verarbeiten, mit einem Kommentar
  markieren, der die Klassifikation angibt (z. B.
  `// classification: PII`).
- Audit-Events für sicherheitsrelevante Aktionen loggen (Login,
  Berechtigungsänderung, Datenexport, Admin-Operationen) — wer, was, wann,
  NICHT die sensible Payload.
- Die CWE-/OWASP-Kategorie für sicherheitsrelevanten Code im Kommentar
  angeben, wenn die Team-Konvention Rückverfolgbarkeit einschließt
  (`// addresses CWE-79 — XSS`).
- Für PCI-Scope den Card-Daten-Code in klar benannte Module separieren,
  damit Scope-Grenzen sichtbar bleiben.
- Für HIPAA-Workloads Verschlüsselung at-rest UND in-transit bevorzugen,
  mit dokumentiertem Key-Management.

### NIE
- PII / PHI / PCI in Log-Nachrichten, Fehlermeldungen oder Telemetrie-
  Events aufnehmen.
- Kartennummern, CVVs oder volle Magnetstreifendaten außerhalb eines
  PCI-DSS-konformen Tokenisierungsdienstes speichern.
- PII-behandelnden Code ohne explizite Klassifikation in allgemeine
  Utility-Module mischen.
- Code generieren, der personenbezogene Daten von EU-Bürgern verarbeitet,
  ohne DSGVO-Pflichten zu berücksichtigen (Recht auf Löschung,
  Datenminimierung, Rechtsgrundlage).
- Workarounds vorschlagen, die Compliance-Kontrollen "für die Entwicklung"
  umgehen — diese Workarounds leaken immer in die Produktion.

### BEKANNTE FALSCH-POSITIVE
- Logs der *Typen* zugegriffener Daten ("Nutzer hat Claim-Record geöffnet")
  sind in der Regel okay; die Regel verbietet das Loggen des *Inhalts*
  sensibler Felder.
- Test-Fixtures mit offensichtlich gefälschten Daten (Telefon `555-0100`,
  PAN `4111-1111-1111-1111`, `John Doe`) sind keine PII.
- Die Aufbewahrung von Audit-Logs ist absichtlich lang (oft Jahre) und
  sollte nicht von allgemeinen Datenaufbewahrungs-Sweeps gefiltert werden.

## Kontext (für Menschen)

Compliance-Rahmenwerke (PCI DSS, HIPAA, SOC 2, ISO 27001, DSGVO)
schreiben Kontrollen vor, sagen Entwicklern aber nicht, welchen Code sie
schreiben sollen. Dieser Skill schließt die Lücke, indem er
kontrollrelevante Hinweise an KI-Generierungsschritte anhängt, damit der
resultierende Code per Default audit-freundlich ist.

## Referenzen

- `frameworks/owasp_mapping.yaml`
- `frameworks/cwe_mapping.yaml`
- [OWASP Top 10 2021](https://owasp.org/Top10/).
- [CWE Top 25 2023](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html).
- [PCI DSS v4.0](https://www.pcisecuritystandards.org/document_library/).
