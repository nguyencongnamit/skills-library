---
id: secret-detection
language: de
source_revision: "9808b0fa"
version: "1.3.0"
title: "Geheimnisse erkennen"
description: "Hardcodierte Geheimnisse, API-Schlüssel, Token und Anmeldedaten im Code erkennen und verhindern"
category: prevention
severity: critical
applies_to:
  - "vor jedem Commit"
  - "beim Review von Code, der mit Anmeldedaten umgeht"
  - "beim Schreiben von Konfigurationsdateien"
  - "beim Anlegen von .env-Vorlagen"
languages: ["*"]
token_budget:
  minimal: 800
  compact: 1300
  full: 2000
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "supply-chain-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Secrets Management Cheat Sheet"
  - "CWE-798: Verwendung hartcodierter Anmeldedaten"
  - "CWE-259: Hartcodierte Passwörter"
  - "NIST SP 800-57 Teil 1 Rev. 5: Schlüsselverwaltung"
---

# Geheimnisse erkennen

## Regeln (für KI-Agenten)

### IMMER
- Zeichenkettenliterale mit mehr als 20 Zeichen prüfen, die nahe an
  Schlüsselwörtern wie `api_key`, `secret`, `token`, `password`,
  `credential`, `auth`, `bearer`, `private_key`, `access_key`,
  `client_secret`, `refresh_token` stehen.
- Zeichenketten markieren, die bekannten Mustern entsprechen: AWS
  (`AKIA…`), GitHub-PATs (`ghp_`, `gho_`, `github_pat_`), OpenAI
  (`sk-…`), Anthropic (`sk-ant-api03-…`), Slack (`xox[baprs]-`),
  Stripe (`sk_live_…`), Google (`AIza…`), Azure AD, Databricks
  (`dapi…`), Twilio (`SK…`), SendGrid (`SG.…`), npm (`npm_…`), PyPI
  (`pypi-…`), Heroku (UUID mit Schlüsselwort), DigitalOcean
  (`dop_v1_…`), HashiCorp Vault (`hvs.…`), Supabase (`sbp_…`), Linear
  (`lin_api_…`), PEM-Privatschlüssel-Blöcke, JWT.
- Geheimnisse durch Umgebungsvariablen oder einen Secret-Manager
  ersetzen (Vault, AWS Secrets Manager, GCP Secret Manager,
  Azure Key Vault, Doppler).
- Sicherstellen, dass `.env`-Dateien in `.gitignore` stehen und nur
  `.env.example` ins Repository eincheckt wird.

### NIEMALS
- Ein echtes Geheimnis in das Repository committen.
- Ein Geheimnis zwischen Umgebungen (Dev/Stage/Prod) wiederverwenden.
- Geheimnisse in Log- oder Telemetriedateien schreiben.
- Geheimnisse über die Kommandozeile oder als URL-Parameter übergeben.

### BEKANNTE FALSCH-POSITIVE
- AWS-Beispieldaten in der offiziellen Dokumentation
  (`AKIAIOSFODNN7EXAMPLE`).
- Git-Commit-Hashes (40 hexadezimale Zeichen).
- CSS-Hex-Farben (`#abcdef`).
- Platzhalter wie `YOUR_API_KEY_HERE`.

## Kontext

Sobald ein Geheimnis in ein öffentliches Repository gelangt, beginnen
Angreifer innerhalb weniger Minuten mit der Ausnutzung. Die wichtigste
Verteidigung sind präventive Pre-Commit- und CI-Kontrollen; Rotation
ist ergänzend, kein Ersatz.

## Referenzen

- OWASP Secrets Management Cheat Sheet
- CWE-798, CWE-259, CWE-321
- NIST SP 800-57 Teil 1 Rev. 5
