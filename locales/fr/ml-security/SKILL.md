---
id: ml-security
language: fr
source_revision: "afe376a8"
version: "1.0.0"
title: "Sécurité ML / LLM"
description: "Prompt injection, model poisoning, attaques de désérialisation, PII dans les données d'entraînement, fuites de secrets dans les notebooks"
category: prevention
severity: high
applies_to:
  - "lors de la génération de code qui appelle une API LLM ou construit un agent piloté par LLM"
  - "lors de la génération de code qui charge des modèles ML depuis disque / Hub / S3"
  - "lors de la génération de pipelines de données qui ingèrent du contenu utilisateur pour du fine-tuning"
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

# Sécurité ML / LLM

## Règles (pour les agents IA)

### TOUJOURS
- Traiter chaque entrée du modèle — y compris les outputs de tools et
  les documents récupérés ré-injectés dans le prompt — comme
  non-fiable. L'injection indirecte de prompt via une page web ou un
  document récupéré est l'attaque LLM la plus courante dans la
  nature.
- Sanitiser et ré-encoder tout ce que le modèle émet avant de
  l'envoyer à un système en aval : SQL builder, shell, file writer,
  requête HTTP, évaluateur de code. La sortie du modèle n'est jamais
  une clé primaire de confiance.
- Imposer un **schema de sortie** par génération structurée (JSON
  Schema, mode function-call, decoding contraint) quand l'étape
  suivante consomme la sortie de manière programmatique. Rejeter
  tout ce qui échoue la validation.
- Maintenir une allowlist de tools / noms de fonctions qu'un modèle
  peut invoquer ; rejeter toute autre invocation. Appliquer
  l'autorisation par-tool au *user humain* de l'agent, pas
  uniquement au modèle.
- Pour le RAG : tamponner les documents récupérés avec leur
  provenance, et séparer "instructions" et "contexte" dans le
  prompt ; ne pas laisser les données récupérées écraser les
  instructions système.
- Lors du chargement de modèles, utiliser **safetensors** pour
  PyTorch et Hugging Face ; utiliser `weights_only=True` avec
  `torch.load` sur PyTorch 2.4+ ; ne jamais charger de fichiers
  `.pkl` / `.pt` arbitraires depuis des sources non-fiables.
- Nettoyer PII, credentials et secrets des données d'entraînement —
  à la source (ingestion), au stockage (chiffrement + contrôle
  d'accès) et en sortie (filtres / détecteurs de réponse).
- Rate-limit / quota sur chaque endpoint adossé à un LLM. Suivre
  la dépense en tokens par tenant.
- Suivre chaque prompt + version de modèle + contexte récupéré
  comme un log d'audit ; rédiger les secrets d'abord.

### JAMAIS
- `pickle.loads` / `joblib.load` / `dill.loads` / `torch.load` d'un
  artefact récupéré à l'exécution depuis une source non-fiable. Ces
  désérialiseurs exécutent du code arbitraire par conception.
- Concaténer l'input utilisateur directement dans un prompt
  contenant des instructions de confiance supérieure : p. ex.
  `f"You are a helpful agent. {user_input}"`. Utiliser une boundary
  templatée plus une séparation explicite par rôle system.
- Donner une string dérivée d'un LLM directement à `eval`, `exec`,
  `os.system`, `subprocess(shell=True)`, `vm.runInNewContext` ou un
  `.raw()` SQL.
- Mettre en dur des clés d'API OpenAI / Anthropic / Cohere dans des
  notebooks ou fichiers du repo. Utiliser des variables
  d'environnement et le skill `secret-detection`.
- Stocker des exemples de données d'entraînement contenant du PII
  dans un stockage long terme sans consentement explicite, fenêtres
  de rétention et APIs de suppression.
- Faire confiance aux paramètres de modèle fournis par le client
  (nom du modèle, system prompt, liste de tools) sans validation
  côté serveur — les clients downgrade vers des modèles moins
  chers / plus faibles / non-autorisés.
- Utiliser un modèle fine-tuné par un vendor externe sans
  vérification de provenance / lignée.
- Cacher les réponses LLM indexées uniquement par texte de prompt
  — ça mélange les contextes utilisateurs quand les prompts
  partagent des préfixes.

### FAUX POSITIFS CONNUS
- Les notebooks de recherche / red-team qui exercent
  intentionnellement des prompts de jailbreak vont dans un
  environnement isolé sans credentials de production.
- Les modèles académiques pré-publication d'auteurs de confiance
  sont souvent distribués en checkpoints `.pt` ; convertir vers
  safetensors comme première étape.
- Les pipelines de génération de données synthétiques peuvent
  légitimement produire du raw output de modèle qui est ensuite
  committé — s'assurer qu'il est étiqueté et revu pour du PII /
  des secrets hallucinés inavertis.

## Contexte (pour les humains)

L'OWASP LLM Top 10 (2025) regroupe les attaques les plus courantes
en dix classes ; **LLM01 Prompt Injection** et **LLM05 Improper
Output Handling** sont les principales préoccupations
opérationnelles car elles s'appliquent à pratiquement chaque déploy
agentique. NIST AI 100-2 cadre les catégories d'ML adversarial
sous-jacentes (évasion, poisoning, extraction) ; MITRE ATLAS fournit
une vue kill-chain.

Ce skill part du principe que Devin (ou tout assistant IA) est
celui qui construit l'app utilisatrice de LLM. Traiter l'app
résultante comme une frontière de sécurité — même quand le « user »
est un autre agent IA.

## Références

- `rules/prompt_injection_patterns.json`
- `rules/unsafe_deserialization.json`
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/).
- [NIST AI 100-2](https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-2e2023.pdf).
- [MITRE ATLAS](https://atlas.mitre.org/).
- [CWE-1426](https://cwe.mitre.org/data/definitions/1426.html) — Improper Validation of Generative AI Output.
