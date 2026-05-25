---
id: supply-chain-security
version: "1.0.0"
title: "Supply Chain Security"
description: "Defend against typosquats, dependency confusion, and malicious package contributions"
category: supply-chain
severity: critical
applies_to:
  - "when AI is asked to add a dependency"
  - "when reviewing PRs that modify package manifests"
  - "when setting up a new project that uses internal namespaces"
  - "before publishing a package to a public registry"
languages: ["*"]
token_budget:
  minimal: 550
  compact: 800
  full: 2100
rules_path: "rules/"
tests_path: "tests/"
related_skills: ["dependency-audit", "secret-detection"]
last_updated: "2026-05-12"
sources:
  - "Alex Birsan, Dependency Confusion (2021)"
  - "OpenSSF Best Practices for OSS Developers"
  - "SLSA Supply-chain Levels for Software Artifacts v1.0"
---

# Supply Chain Security

## Rules (for AI agents)

### ALWAYS
- Compute Levenshtein distance against the top-1000 list for the relevant ecosystem
  whenever proposing a new dependency. Flag any candidate with distance ≤ 2 from a
  popular package (`axois` vs `axios`, `urlib3` vs `urllib3`, `colours` vs `colors`,
  `python-dateutil` vs `dateutil` vs `dateutils`).
- Verify that internal-namespace packages (`@yourco/*`, `com.yourco.*`) are pulled from
  the internal registry, not the public one. Configure `.npmrc` /
  `pip.conf` / `settings.gradle` with the internal scope explicitly.
- Pin the registry URL in lockfiles to prevent registry redirection attacks.
- Check that any newly added package has a verified maintainer (`npm` provenance,
  `sigstore` signature, or GPG-signed git tag) when published in the last 90 days.
- Treat install scripts (`postinstall`, `preinstall`, `setup.py` arbitrary code,
  `build.rs`) as high-risk surface and flag them in the PR description for human
  review.

### NEVER
- Add a public package whose name matches an internal namespace pattern.
- Trust a package whose repository URL on the registry page does not match its actual
  source repo.
- Recommend a freshly-published package with low download counts for a security-critical
  use case (auth, crypto, HTTP, DB drivers).
- Disable the package manager's integrity check (`--no-package-lock`, `--ignore-scripts
  = false` when defending against it, `npm config set audit false` in production).
- Auto-merge dependency-bump PRs without a reviewer when the bump crosses a major
  version.
- Suggest installing tools via `curl | sh` patterns from untrusted sources.

### KNOWN FALSE POSITIVES
- Legitimate orgs forking and republishing maintained packages with a `-fork` or
  `-community` suffix; verify the fork's repo URL before flagging.
- Beta / alpha releases of well-known packages (e.g. `next@canary`) appear "newly
  published" but are part of a known release cadence.
- Internal namespace packages (`@yourco/internal-tools`) intentionally not on the
  public registry — these are fine when the `.npmrc` is configured correctly.

## Context (for humans)

The dependency-confusion attack class works because most package managers default to
preferring the highest-version package across all configured registries. If an
attacker publishes `@yourco/internal-tool@99.9.9` to npmjs.com, every `npm install` in
your team's project pulls the attacker's code instead of the legitimate internal one.

Typosquats are equally devastating but exploit human attention instead of registry
defaults. AI tools are especially prone because they generate plausible-looking
package names without checking which ones actually exist.

## References

- `rules/typosquat_patterns.json`
- `rules/dependency_confusion.json`
- [Alex Birsan's original dependency confusion writeup](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610).
- [SLSA](https://slsa.dev/).
