---
id: ml-security
language: de
source_revision: "afe376a8"
version: "1.0.0"
title: "ML-/LLM-Sicherheit"
description: "Prompt Injection, Model Poisoning, Deserialisierungs-Angriffe, PII in Trainingsdaten, Secret-Leaks in Notebooks"
category: prevention
severity: high
applies_to:
  - "beim Erzeugen von Code, der eine LLM-API aufruft oder einen LLM-getriebenen Agenten baut"
  - "beim Erzeugen von Code, der ML-Modelle von Disk / Hub / S3 lädt"
  - "beim Erzeugen von Datenpipelines, die User-Content für Fine-Tuning ingestieren"
languages: ["python", "javascript", "typescript", "jupyter", "go"]
token_budget:
  minimal: 1000
  compact: 1200
  full: 2700
rules_path: "rules/"
related_skills: ["secret-detection", "supply-chain-security", "api-security"]
last_updated: "2026-05-13"
sources:
  - "OWASP Top 10 for LLM Applications 2025"
  - "NIST AI 100-2 (Adversarial Machine Learning)"
  - "MITRE ATLAS (Adversarial Threat Landscape for AI Systems)"
  - "CWE-502, CWE-1039, CWE-1426"
---

# ML-/LLM-Sicherheit

## Regeln (für KI-Agenten)

### IMMER
- Jedes Modell-Input — inklusive Tool-Outputs und in den Prompt
  zurückgespeister Retrieval-Dokumente — als nicht vertrauenswürdig
  behandeln. Indirekte Prompt Injection über eine abgerufene Webseite
  oder ein Dokument ist der häufigste LLM-Angriff in freier Wildbahn.
- Alles, was das Modell emittiert, sanitisieren und neu encodieren,
  bevor es an ein Downstream-System geht: SQL-Builder, Shell,
  File-Writer, HTTP-Request, Code-Evaluator. Modell-Output ist nie
  ein Primärschlüssel für Vertrauen.
- Ein **Output-Schema** mit strukturierter Generierung erzwingen
  (JSON Schema, Function-Call-Modus, constrained decoding), wenn
  der nächste Schritt das Output programmatisch konsumiert. Alles,
  was die Validierung nicht besteht, ablehnen.
- Eine Allowlist von Tools / Funktionsnamen pflegen, die ein Modell
  aufrufen darf; jede andere Invocation ablehnen. Pro-Tool-
  Autorisierung auf den *menschlichen User* des Agenten anwenden,
  nicht nur auf das Modell.
- Für RAG: abgerufene Dokumente mit Provenance stempeln und im
  Prompt "Instructions" von "Context" trennen; abgerufene Daten
  dürfen System-Instructions nicht überschreiben.
- Beim Laden von Modellen **safetensors** für PyTorch und Hugging
  Face verwenden; `weights_only=True` mit `torch.load` auf PyTorch
  2.4+; niemals beliebige `.pkl` / `.pt`-Dateien aus nicht
  vertrauenswürdigen Quellen laden.
- PII, Credentials und Secrets aus Trainingsdaten entfernen — an
  der Quelle (Data Ingestion), bei der Speicherung (Encryption +
  Access Control) und beim Output (Response-Filter / -Detektoren).
- Rate-Limit / Quota an jedem LLM-Backed-Endpunkt. Token-Spend pro
  Tenant tracken.
- Jeden Prompt + Modell-Version + abgerufenen Kontext als
  Audit-Log tracken; Secrets vorher redacten.

### NIE
- Ein zur Laufzeit aus nicht vertrauenswürdiger Quelle geholtes
  Artefakt mit `pickle.loads` / `joblib.load` / `dill.loads` /
  `torch.load` laden. Diese Deserializer führen per Design
  beliebigen Code aus.
- User-Input direkt an einen Prompt mit höher vertrauten
  Instructions konkatenieren: z. B.
  `f"You are a helpful agent. {user_input}"`. Eine getemplatete
  Boundary plus explizite System-Rollen-Trennung verwenden.
- Einen LLM-abgeleiteten String direkt an `eval`, `exec`,
  `os.system`, `subprocess(shell=True)`, `vm.runInNewContext`
  oder einen `.raw()`-SQL-Call geben.
- OpenAI- / Anthropic- / Cohere-API-Keys in Notebooks oder
  Repo-Dateien hardcoden. Environment Variables und den
  `secret-detection`-Skill verwenden.
- Trainingsdaten-Beispiele mit PII in Langzeitspeicher legen ohne
  explizite Einwilligung, Retention-Fenster und Lösch-APIs.
- Client-gelieferten Modell-Parametern (Modellname, System-Prompt,
  Tool-Liste) ohne Server-Side-Validierung vertrauen — Clients
  downgraden auf billigere / schwächere / unautorisierte Modelle.
- Ein vom externen Vendor fine-getuntes Modell ohne Provenance-/
  Lineage-Verifizierung verwenden.
- LLM-Responses nur per Prompt-Text indizieren und cachen — das
  vermischt User-Kontexte, wenn Prompts gemeinsame Präfixe haben.

### BEKANNTE FALSCH-POSITIVE
- Research-/Red-Team-Notebooks, die absichtlich Jailbreak-Prompts
  ausführen, gehören in eine isolierte Umgebung ohne Produktions-
  Credentials.
- Pre-Publication-Academic-Modelle von vertrauenswürdigen Autoren
  werden oft als `.pt`-Checkpoints verteilt; als ersten Schritt zu
  safetensors konvertieren.
- Synthetic-Data-Generation-Pipelines können legitim rohes Modell-
  Output produzieren, das dann committed wird — sicherstellen,
  dass es gelabelt und auf versehentliches PII / halluzinierte
  Secrets reviewed ist.

## Kontext (für Menschen)

Die OWASP LLM Top 10 (2025) fassen die häufigsten Angriffe in zehn
Klassen; **LLM01 Prompt Injection** und **LLM05 Improper Output
Handling** sind die zentralen operativen Sorgen, weil sie auf
praktisch jeden Agentic-Deploy zutreffen. NIST AI 100-2 rahmt die
zugrunde liegenden Adversarial-ML-Kategorien (Evasion, Poisoning,
Extraction); MITRE ATLAS bietet eine Kill-Chain-Sicht.

Dieser Skill geht davon aus, dass Devin (oder ein beliebiger
KI-Assistent) derjenige ist, der die LLM-nutzende App baut. Die
resultierende App als Sicherheitsgrenze behandeln — auch wenn der
"User" ein anderer KI-Agent ist.

## Referenzen

- `rules/prompt_injection_patterns.json`
- `rules/unsafe_deserialization.json`
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- [NIST AI 100-2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf).
- [MITRE ATLAS](https://atlas.mitre.org/).
- [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) — Improper Validation of Generative AI Output.
