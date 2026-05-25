#!/usr/bin/env bash
# Top-level eval harness for skills-library.
#
# Runs every check that can be evaluated *without* a live LLM:
#
#   1. `skills-check test secret-detection` over the corpus (passes
#      go-side regex parity + denylist + hotword logic).
#   2. The Python precision/recall benchmark (skills-library vs
#      gitleaks if installed). Output is written to
#      evals/baselines/secret-detection-static.md so the report is
#      diffable in PRs.
#   3. Static well-formedness checks on each fixture directory:
#      every fixture has an `expected.json` (or pointer README),
#      every `expected.json` parses, every cited `source` path
#      resolves to a real file in the repo.
#
# Items that require an LLM (the three `*.json` baselines under
# `baselines/`) are NOT executed by this script — see the README.
#
# Exit code: 0 on success, non-zero on the first failure.

set -euo pipefail

cd "$(dirname "$0")/.."   # repo root

echo "==> 1. skills-check test secret-detection"
if ! command -v skills-check >/dev/null 2>&1; then
  if [[ -x ./skills-check ]]; then
    ALIAS=./skills-check
  elif [[ -x /tmp/skills-check ]]; then
    ALIAS=/tmp/skills-check
  else
    echo "    building skills-check ..."
    (cd cmd/skills-check && go build -o ../../skills-check)
    ALIAS=./skills-check
  fi
else
  ALIAS=skills-check
fi
"$ALIAS" test secret-detection

echo
echo "==> 2. precision/recall benchmark"
# Use a bash array, not an unquoted string, so a gitleaks binary path that
# contains spaces is passed through as a single argv element. Unquoted
# expansion would word-split such a path into multiple argparse arguments.
if [[ "${SKIP_GITLEAKS:-}" == "1" ]]; then
  GITLEAKS_OPT=(--gitleaks skip)
elif command -v gitleaks >/dev/null 2>&1; then
  GITLEAKS_OPT=(--gitleaks "$(command -v gitleaks)")
elif [[ -x "$HOME/go/bin/gitleaks" ]]; then
  GITLEAKS_OPT=(--gitleaks "$HOME/go/bin/gitleaks")
else
  GITLEAKS_OPT=(--gitleaks skip)
fi
python3 evals/benchmarks/secret-detection-vs-gitleaks.py \
  "${GITLEAKS_OPT[@]}" \
  --out evals/baselines/secret-detection-static.md
cat evals/baselines/secret-detection-static.md

echo
echo "==> 3. fixture well-formedness"
python3 - <<'PY'
import json, pathlib, sys
ROOT = pathlib.Path(".").resolve()
fail = 0
for exp in (ROOT / "evals/fixtures").rglob("expected.json"):
    try:
        d = json.loads(exp.read_text())
    except Exception as e:
        print(f"FAIL {exp}: invalid JSON: {e}")
        fail = 1
        continue
    for finding in d.get("expected_findings", []):
        src = finding.get("source")
        if src and not (ROOT / src).exists():
            print(f"FAIL {exp}: cited source path missing: {src}")
            fail = 1
for exp in (ROOT / "evals/fixtures").rglob("*.expected.json"):
    try:
        d = json.loads(exp.read_text())
    except Exception as e:
        print(f"FAIL {exp}: invalid JSON: {e}")
        fail = 1
        continue
    for finding in d.get("expected_findings", []):
        src = finding.get("source")
        if src and not (ROOT / src).exists():
            print(f"FAIL {exp}: cited source path missing: {src}")
            fail = 1
sys.exit(fail)
PY
echo "    fixture cross-references OK"

echo
echo "==> 4. scanner-eval (dependencies / cicd / dockerfile)"
# The scanner-eval harness drives skills-mcp over JSON-RPC and scores
# every fixture under evals/fixtures/{dependency-choice,
# cicd-hardening, docker-hardening}/ against its expected.json. The
# harness builds skills-mcp on demand if no binary is on PATH.
python3 evals/benchmarks/scanner-eval.py \
  --out evals/baselines/scanner-eval-static.md \
  --verbose
cat evals/baselines/scanner-eval-static.md

echo
echo "==> all eval checks passed"
