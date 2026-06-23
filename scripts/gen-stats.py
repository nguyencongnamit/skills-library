#!/usr/bin/env python3
"""Derive the homepage "by the numbers" stats from their source-of-truth files
and write docs/assets/data/stats.json, so the homepage stays in sync with the
repo automatically (no hand-editing index.md). Run as part of `make docs-data`.

Counts (each from a single authoritative source):
  - cve_patterns          : entries in vulnerabilities/cve/code-relevant/cve_patterns.json
  - secret_patterns       : `- id:` checks under `checks:` in the secret-detection checklist
  - assistant_integrations: names in compiler.AllTools() (the canonical distribution formatters)

The malicious-package / ecosystem / skills counts are derived client-side from
the existing malicious-packages.json / skills.json datasets; this file covers
the remaining curated numbers that have no other shipped dataset.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "docs" / "assets" / "data" / "stats.json"


def cve_patterns() -> int:
    d = json.loads((REPO / "vulnerabilities" / "cve" / "code-relevant" / "cve_patterns.json").read_text())
    entries = d.get("entries", d if isinstance(d, list) else d.get("patterns", []))
    return len(entries)


def secret_patterns() -> int:
    text = (REPO / "skills" / "secret-detection" / "checklists" / "secret_detection.yaml").read_text()
    count = 0
    in_checks = False
    for line in text.splitlines():
        if re.match(r"^checks:", line):
            in_checks = True
            continue
        if in_checks and re.match(r"^[A-Za-z_]+:", line):  # next top-level key
            in_checks = False
        if in_checks and re.match(r"^- id:", line):
            count += 1
    return count


def assistant_integrations() -> int:
    text = (REPO / "cmd" / "skills-check" / "internal" / "compiler" / "compiler.go").read_text()
    m = re.search(r"func AllTools\(\).*?names\s*:?=\s*\[\]string\{([^}]*)\}", text, re.DOTALL)
    if not m:
        raise SystemExit("gen-stats: could not locate compiler.AllTools() names slice")
    return len(re.findall(r'"[^"]+"', m.group(1)))


def main() -> int:
    stats = {
        "cve_patterns": cve_patterns(),
        "secret_patterns": secret_patterns(),
        "assistant_integrations": assistant_integrations(),
    }
    OUT.write_text(json.dumps(stats, indent=2) + "\n")
    print(f"wrote {OUT.relative_to(REPO)} — {stats}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
