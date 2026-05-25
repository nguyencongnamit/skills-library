#!/usr/bin/env python3
"""Generate locale stub SKILL.md files for missing locale × skill cells.

For each skill in skills/*/SKILL.md and each target locale in TARGET_LOCALES,
checks if locales/<locale>/<skill-id>/SKILL.md exists. If not, the script:

1. Reads the English SKILL.md.
2. Splits frontmatter from body.
3. Inserts `language: <bcp47>` (and `dir: rtl` for Arabic) into the
   frontmatter immediately after `id:`.
4. Prepends a `> ⚠️ TRANSLATION PENDING ...` banner before the body
   so downstream consumers know this is the English original, not a
   translation.
5. Writes the result to locales/<locale>/<skill-id>/SKILL.md.

Existing translated SKILL.md files (real translations, not stubs) are
left untouched — the script never overwrites an existing file.

Usage:
    python3 scripts/generate-locale-stubs.py [--locale es] [--dry-run]

By default writes stubs for every (locale × skill) cell that is missing.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Iterable

TARGET_LOCALES = ["es", "fr", "de", "ar", "zh-Hans", "pt-BR"]
RTL_LOCALES = {"ar"}

# Banner localization is intentionally English-only — the banner exists
# so that a human contributor knows the body has not been translated yet
# and so that an LLM consuming the file knows it is reading an English
# original. Translating the banner would obscure that signal.
BANNER = (
    "> ⚠️ **TRANSLATION PENDING** — this file is a stub: the frontmatter "
    "carries the `language: {locale}` marker but the body below is the "
    "untranslated English original. Translate the prose, then remove "
    "this banner.\n"
)

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n", re.DOTALL)


def split_frontmatter(text: str) -> tuple[str, str]:
    """Return (frontmatter_block_without_fences, body_after_fences).

    Raises ValueError if the file does not have a leading YAML
    frontmatter block delimited by `---` fences.
    """
    m = FRONTMATTER_RE.match(text)
    if not m:
        raise ValueError("file is missing leading --- YAML frontmatter block")
    return m.group(1), text[m.end() :]


def insert_language_field(frontmatter: str, locale: str) -> str:
    """Insert `language: <locale>` (and `dir: rtl` for RTL locales)
    into the frontmatter directly after the `id:` line.

    If a `language:` line already exists it is replaced; if `dir:` is
    needed it is inserted alongside `language:`.
    """
    lines = frontmatter.splitlines()
    out: list[str] = []
    inserted_language = False
    inserted_dir = False
    needs_dir = locale in RTL_LOCALES
    for ln in lines:
        if ln.startswith("language:"):
            out.append(f"language: {locale}")
            inserted_language = True
            continue
        if ln.startswith("dir:"):
            if needs_dir:
                out.append("dir: rtl")
                inserted_dir = True
                continue
            # If the source somehow has a `dir:` we don't need, drop it.
            continue
        out.append(ln)
        if not inserted_language and ln.startswith("id:"):
            out.append(f"language: {locale}")
            inserted_language = True
            if needs_dir and not inserted_dir:
                out.append("dir: rtl")
                inserted_dir = True
    if not inserted_language:
        out.insert(0, f"language: {locale}")
        if needs_dir:
            out.insert(1, "dir: rtl")
    return "\n".join(out)


def build_stub(english_text: str, locale: str) -> str:
    """Return the stub SKILL.md content for the given locale."""
    fm, body = split_frontmatter(english_text)
    new_fm = insert_language_field(fm, locale)
    banner = BANNER.format(locale=locale)
    body_lstripped = body.lstrip("\n")
    return f"---\n{new_fm}\n---\n\n{banner}\n{body_lstripped}"


def iter_skill_files(skills_dir: Path) -> Iterable[tuple[str, Path]]:
    for child in sorted(skills_dir.iterdir()):
        skill_md = child / "SKILL.md"
        if skill_md.is_file():
            yield child.name, skill_md


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent.parent
    skills_dir = repo_root / "skills"
    locales_dir = repo_root / "locales"
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--locale",
        choices=TARGET_LOCALES,
        action="append",
        help="restrict generation to a single locale (repeatable). "
        "Default: every locale in TARGET_LOCALES.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="report what would be written but don't touch disk",
    )
    args = parser.parse_args(argv)
    locales = args.locale if args.locale else TARGET_LOCALES
    skill_files = list(iter_skill_files(skills_dir))
    if not skill_files:
        print(f"no SKILL.md files found under {skills_dir}", file=sys.stderr)
        return 1
    written = 0
    skipped = 0
    for locale in locales:
        for skill_id, english_path in skill_files:
            out_path = locales_dir / locale / skill_id / "SKILL.md"
            if out_path.exists():
                skipped += 1
                continue
            try:
                stub = build_stub(english_path.read_text(encoding="utf-8"), locale)
            except ValueError as e:
                print(f"skip {english_path}: {e}", file=sys.stderr)
                continue
            if args.dry_run:
                print(f"would write {out_path.relative_to(repo_root)}")
                written += 1
                continue
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(stub, encoding="utf-8")
            written += 1
    print(
        f"locale stubs: wrote {written} new file(s), "
        f"left {skipped} existing translation(s) untouched"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
