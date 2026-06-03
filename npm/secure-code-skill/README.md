# @namncqualgo/secure-code-skill

Installs the **secure-code** security skills into a Claude Code project, and
optionally connects an MCP server for active scanning. The skills are
self-contained knowledge (28 skills: secret detection, dependency/CVE hygiene,
container & IaC hardening, …) — they work **with no MCP required**.

## Install the skills

```sh
npx @namncqualgo/secure-code-skill init          # into ./.claude/skills
npx @namncqualgo/secure-code-skill init ./app    # into ./app/.claude/skills
```

Claude Code picks them up automatically in that project — Claude now passively
knows the security rules and applies them while reading and writing code.

## Add active scanning (optional)

The skills are knowledge; the **secure-code MCP** adds precise automated
scanners (a multi-pattern secret engine, an offline OSV cache, Dockerfile /
GitHub Actions checks). Connect it to Claude Code:

```sh
npx @namncqualgo/secure-code-skill connect-mcp
# runs: claude mcp add secure-code -- npx -y @namncqualgo/secure-code-mcp
```

`connect-mcp` is generic — it can register **any** MCP server, not just ours:

```sh
npx @namncqualgo/secure-code-skill connect-mcp semgrep -- npx -y @semgrep/mcp
npx @namncqualgo/secure-code-skill connect-mcp --user    # user (global) scope
```

If the Claude CLI isn't on PATH, the command prints the exact `claude mcp add`
line (and the JSON config) to run yourself.

## Relationship to the other package

- **`@namncqualgo/secure-code-skill`** (this) — the skills + a thin connector.
  Binary-free, tiny.
- **`@namncqualgo/secure-code-mcp`** — the MCP engine (Go binary + data),
  agent-agnostic. Use it standalone in any MCP client, or let `connect-mcp`
  wire it into Claude Code.

The skill works alone; the MCP makes it sharper. Neither requires the other.

## License

Apache-2.0. See the [repository](https://github.com/namncqualgo/skills-library).
