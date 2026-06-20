#!/usr/bin/env bash
# preflight — the one command to run before opening a PR.
#
# Runs every gate CI runs, in order, and prints a single green/red summary.
# "Vibe secure code": scaffold with `skills-check new <id>`, edit the SKILL.md,
# then run this. If it's green, your contribution passes — author be human or AI.
#
#   ./scripts/preflight.sh
#
# Trust comes from the gates passing, not from who typed the code.
set -uo pipefail

cd "$(dirname "$0")/.." || exit 2
ROOT="$(pwd)"

bold=$(printf '\033[1m'); green=$(printf '\033[32m'); red=$(printf '\033[31m')
dim=$(printf '\033[2m');  reset=$(printf '\033[0m')

FAILED=()

# Always build the CLI from the current source before checking. A stale
# ./skills-check binary regenerates old output and produces a wall of false
# failures (drift / out-of-sync) that have nothing to do with your change —
# the fastest way to destroy trust in this gate. Build fresh, every time.
printf '%s==> building skills-check from current source%s\n' "$bold" "$reset"
if go build -o ./skills-check ./cmd/skills-check; then
  CHECK=(./skills-check)
else
  printf '%s build failed%s — cannot preflight.\n' "$red" "$reset"
  exit 2
fi
step() { printf '\n%s==> %s%s\n' "$bold" "$1" "$reset"; }
ok()   { printf '%s  ok%s  %s\n'   "$green" "$reset" "$1"; }
bad()  { printf '%s fail%s %s\n'   "$red"   "$reset" "$1"; FAILED+=("$1"); }

# 1. Validate every SKILL.md, rule file, and checklist.
step "validate"
if "${CHECK[@]}" validate; then ok "validate"; else bad "validate"; fi

# 2. Full Go test suite.
step "go test ./..."
if go test ./...; then ok "go test"; else bad "go test"; fi

# 3. Regenerate dist/ and fail on any drift (CI rejects uncommitted regen output).
step "regenerate (drift check)"
if "${CHECK[@]}" regenerate >/dev/null; then
  if git diff --quiet -- dist/ 2>/dev/null; then
    ok "regenerate (no drift)"
  else
    bad "regenerate — dist/ changed; commit the regenerated files"
    printf '%s' "$dim"; git diff --stat -- dist/ 2>/dev/null; printf '%s' "$reset"
  fi
else
  bad "regenerate"
fi

# 4. derive-checklists --check for every skill (no-op for skills without markers).
step "derive-checklists --check (all skills)"
DRIFT=()
for d in skills/*/; do
  id="$(basename "$d")"
  if ! "${CHECK[@]}" derive-checklists "$id" --check >/dev/null 2>&1; then
    DRIFT+=("$id")
  fi
done
if [ "${#DRIFT[@]}" -eq 0 ]; then
  ok "derive-checklists (all in sync)"
else
  bad "derive-checklists out of sync: ${DRIFT[*]}"
  printf '%s    re-run: skills-check derive-checklists <id>%s\n' "$dim" "$reset"
fi

# 5. Manifest checksums in sync (read-only verify).
step "manifest verify --checksums-only"
if "${CHECK[@]}" manifest verify --checksums-only --path . >/dev/null 2>&1; then
  ok "manifest checksums"
else
  bad "manifest — run: skills-check manifest compute --path . --write"
fi

# 6. Prevention-lift gate. Every skill that ships an evals/cases.json must keep
# its prevention lift at or above its floor (per-skill min_lift in the corpus,
# else the --min-lift default). A regression that lets the AI write insecure
# code the skill used to prevent fails here — the same hard gate CI enforces, so
# local and CI agree. This is the objective, eval-gated bar (VISION §5).
step "eval --all --enforce (prevention-lift gate)"
if "${CHECK[@]}" eval --all --enforce; then ok "eval (prevention lift)"; else bad "eval — a skill dropped below its prevention-lift floor"; fi

# Summary.
printf '\n%s────────────────────────────────────────%s\n' "$dim" "$reset"
if [ "${#FAILED[@]}" -eq 0 ]; then
  printf '%s✓ preflight passed%s — open the PR.\n' "$green" "$reset"
  exit 0
fi
printf '%s✗ preflight failed%s (%d):\n' "$red" "$reset" "${#FAILED[@]}"
for f in "${FAILED[@]}"; do printf '   - %s\n' "$f"; done
printf '\nFix the above, then re-run %s./scripts/preflight.sh%s\n' "$bold" "$reset"
exit 1
