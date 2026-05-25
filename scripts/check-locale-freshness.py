#!/usr/bin/env python3
"""Locale freshness check.

Walks every ``locales/<bcp47>/<skill-id>/SKILL.md`` and enforces:

1. The file declares a ``language`` field in its YAML frontmatter that
   matches the directory's ``<bcp47>``.
2. Exactly one of the following holds:
   a) The body still starts with the ``TRANSLATION PENDING`` banner —
      a stub awaiting a real translation. The file is exempt from
      the ``source_revision`` check below.
   b) The frontmatter declares ``source_revision: <commit-sha>`` and
      that revision still exists in the working git repo. A warning
      is emitted (NOT a failure) if the English
      ``skills/<skill-id>/SKILL.md`` has been modified at HEAD relative
      to ``source_revision``, since the translation may have drifted.

The script exits non-zero on (1) failures and on (2b) malformed
``source_revision`` values that don't resolve to a real commit.
Drift between the English commit and HEAD is reported as a warning
only — translators may legitimately track the English original
slowly and a hard failure would block routine English edits.

Usage::

    python3 scripts/check-locale-freshness.py             # check all locales
    python3 scripts/check-locale-freshness.py --locale es # one locale
    python3 scripts/check-locale-freshness.py --strict    # warnings fail too
"""

from __future__ import annotations

import argparse
import pathlib
import re
import subprocess
import sys

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
LOCALES_ROOT = REPO_ROOT / "locales"
SKILLS_ROOT = REPO_ROOT / "skills"

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n(.*)$", re.S)
PENDING_BANNER_RE = re.compile(
    r"^\s*>\s*(?:⚠️|:warning:)?\s*\*{0,2}\s*TRANSLATION PENDING",
    re.M,
)


def _split_frontmatter(text: str) -> tuple[dict[str, str], str] | None:
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None
    fm: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if ":" in line and not line.startswith(" "):
            k, _, v = line.partition(":")
            fm[k.strip()] = v.strip()
    return fm, m.group(2)


def _git_object_exists(sha: str) -> bool:
    """Whether `sha` resolves to a commit reachable in the local repo.

    Earlier versions only ran `git cat-file -e <sha>`, which accepts any
    git object — a blob or tree SHA that happens to match a typoed
    `source_revision` would pass the existence check but then fail the
    drift / diff lookups silently. Resolve `<sha>^{commit}` instead so
    only real commit objects qualify.
    """
    try:
        subprocess.run(
            ["git", "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
        )
        return True
    except subprocess.CalledProcessError:
        return False


def _english_changed_since(skill_id: str, revision: str) -> bool:
    """Has skills/<skill-id>/SKILL.md changed at HEAD vs the named revision?"""
    skill_path = f"skills/{skill_id}/SKILL.md"
    try:
        out = subprocess.run(
            ["git", "diff", "--name-only", f"{revision}..HEAD", "--", skill_path],
            cwd=REPO_ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        return bool(out.strip())
    except subprocess.CalledProcessError:
        return False


def check_file(
    path: pathlib.Path,
    expected_locale: str,
    skill_id: str,
) -> tuple[list[str], list[str]]:
    """Return (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []
    text = path.read_text(encoding="utf-8")
    split = _split_frontmatter(text)
    if not split:
        errors.append("no YAML frontmatter")
        return errors, warnings
    fm, body = split
    lang = fm.get("language", "")
    if lang != expected_locale:
        errors.append(
            f"language field is {lang!r}, expected {expected_locale!r}"
        )

    is_stub = bool(PENDING_BANNER_RE.search(body[:512]))
    source_rev = fm.get("source_revision", "").strip()

    if is_stub:
        # Stubs are exempt from source_revision checks because they're
        # known-untranslated. If a stub happens to carry source_revision
        # it's harmless.
        return errors, warnings

    if not source_rev:
        errors.append(
            "non-stub translation is missing source_revision in frontmatter"
        )
        return errors, warnings

    # Strip optional surrounding quotes.
    source_rev = source_rev.strip("'\"")
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", source_rev):
        errors.append(f"source_revision {source_rev!r} is not a git sha-ish")
        return errors, warnings

    if not _git_object_exists(source_rev):
        errors.append(
            f"source_revision {source_rev!r} does not exist in the repo"
        )
        return errors, warnings

    if _english_changed_since(skill_id, source_rev):
        warnings.append(
            f"English skill changed since {source_rev}; translation may have drifted"
        )

    return errors, warnings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--locale",
        action="append",
        default=None,
        help="Restrict to one or more locales. Repeatable.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Treat warnings as failures.",
    )
    args = parser.parse_args(argv)

    if not LOCALES_ROOT.exists():
        print("no locales/ directory; nothing to check")
        return 0

    locales = (
        sorted(args.locale)
        if args.locale
        else sorted(p.name for p in LOCALES_ROOT.iterdir() if p.is_dir())
    )

    total_errors = 0
    total_warnings = 0
    for locale in locales:
        locale_root = LOCALES_ROOT / locale
        if not locale_root.is_dir():
            print(f"warn: no such locale: {locale}")
            continue
        for skill_dir in sorted(p for p in locale_root.iterdir() if p.is_dir()):
            skill_id = skill_dir.name
            skill_md = skill_dir / "SKILL.md"
            if not skill_md.exists():
                continue
            errs, warns = check_file(skill_md, locale, skill_id)
            rel = skill_md.relative_to(REPO_ROOT).as_posix()
            for e in errs:
                print(f"error: {rel}: {e}", file=sys.stderr)
                total_errors += 1
            for w in warns:
                print(f"warn: {rel}: {w}", file=sys.stderr)
                total_warnings += 1

    if total_errors:
        print(
            f"FAIL: {total_errors} error(s), {total_warnings} warning(s)",
            file=sys.stderr,
        )
        return 1
    if args.strict and total_warnings:
        print(
            f"FAIL (strict): {total_warnings} warning(s)",
            file=sys.stderr,
        )
        return 1
    print(
        f"ok: {len(locales)} locale(s) checked, {total_warnings} warning(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
