# @namncqualgo/secure-code-skill

Installs the **secure-code** security skills (28 skills: secret detection,
dependency / CVE hygiene, container & IaC hardening, …) into a project for your
AI coding tool, and optionally connects an MCP server for active scanning. The
skills are self-contained knowledge — they work **with no MCP required**.

## Install the skills

```sh
npx @namncqualgo/secure-code-skill init                    # Claude Code (default)
npx @namncqualgo/secure-code-skill init --tool cursor      # Cursor
npx @namncqualgo/secure-code-skill init ./app --tool copilot
```

`--tool` picks the format each tool consumes. Where the tool supports it, the
skills install as **context-scoped** rules — only the rule relevant to the
files you're editing loads, instead of one always-on blob (the same
progressive-disclosure benefit Claude Code gets from `.claude/skills`).

| `--tool` | Installs into | Scoped? |
|----------|---------------|---------|
| `claude` *(default)* | `.claude/skills/` (28 native skills) | ✅ per-skill |
| `cursor` | `.cursor/rules/*.mdc` (globs / agent-requested) | ✅ per-skill |
| `copilot` | `.github/instructions/*.instructions.md` (`applyTo`) | ✅ per-skill |
| `devin` | `.devin/rules/*.md` (glob / model-decision) | ✅ per-skill |
| `cline` | `.clinerules` | ⚠️ single file |
| `codex` | `AGENTS.md` | ⚠️ single file |
| `universal` | `SECURITY-SKILLS.md` | ⚠️ single file |

(`cline` / `codex` / `universal` get a single always-on file — those tools have
no per-rule scoping mechanism.)

## Add active scanning (optional)

The skills are knowledge; the **secure-code MCP** adds precise automated
scanners (a multi-pattern secret engine, an offline OSV cache, Dockerfile /
GitHub Actions checks). Connect it to Claude Code:

```sh
npx @namncqualgo/secure-code-skill connect-mcp
# runs: claude mcp add secure-code -- npx -y @namncqualgo/secure-code-mcp
```

`connect-mcp` is generic — it can register **any** MCP server:

```sh
npx @namncqualgo/secure-code-skill connect-mcp semgrep -- npx -y @semgrep/mcp
npx @namncqualgo/secure-code-skill connect-mcp --user    # user (global) scope
```

If the Claude CLI isn't on PATH, the command prints the exact `claude mcp add`
line (and the JSON config) to run yourself.

## Relationship to the other package

- **`@namncqualgo/secure-code-skill`** (this) — the skills + a thin connector.
  Binary-free.
- **`@namncqualgo/secure-code-mcp`** — the MCP engine (Go binary + data),
  agent-agnostic. Use it standalone in any MCP client, or let `connect-mcp`
  wire it into Claude Code.

The skill works alone; the MCP makes it sharper. Neither requires the other.

## License

Apache-2.0. See the [repository](https://github.com/namncqualgo/skills-library).
