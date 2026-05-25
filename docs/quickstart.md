# Quick Start

Get SkillShield into a project in under five minutes. The fastest path is the static `CLAUDE.md` drop; the most powerful path is the MCP server.

!!! note "Prerequisites"
    - **Go 1.22+** to build from source (or grab a release binary once v1.0 ships)
    - **An AI coding assistant**: Claude Code, Cursor, Copilot, Codex, Windsurf, Cline, Antigravity, or Devin
    - **No network needed at runtime.** The library works fully offline from the first `git clone`. Updates are optional.

## 1. Clone and build

```bash
git clone https://github.com/namncqualgo/skills-library.git
cd skills-library
go build -trimpath -ldflags "-s -w" -o skills-check ./cmd/skills-check
go build -trimpath -ldflags "-s -w" -o skills-mcp   ./cmd/skills-mcp
```

That produces two single-file binaries. The CLI generates IDE config files; the MCP server exposes 15 JSON-RPC tools.

!!! tip "Sanity check"
    Run `./skills-check validate` — it should report `28 skills validated`. If you see anything else, your clone is incomplete or corrupted.

## 2. Drop a static config into a project (fastest path)

```bash
# in any project you want to make security-aware:
/path/to/skills-library/skills-check init \
  --tool claude \
  --skills secret-detection,dependency-audit,secure-code-review \
  --budget compact
```

That writes a `CLAUDE.md` containing only the skills you picked, at the compact (~2k tokens) budget tier. The next time you open the project in Claude Code, those rules are in the assistant's context.

Other targets: `--tool cursor | copilot | codex | windsurf | cline | devin | universal`. Other tiers: `--budget minimal | compact | full`.

!!! note "Pre-compiled bundles"
    If you don't care about cherry-picking, just copy the pre-compiled file from `dist/`:
    ```bash
    cp /path/to/skills-library/dist/CLAUDE.md /your-project/CLAUDE.md
    ```
    Symlink instead of copy if you want it to auto-update when you `git pull` the library.

## 3. Wire the MCP server (most powerful path)

This gives the assistant on-demand access to 15 JSON-RPC tools — vulnerability lookups, dependency scans, Dockerfile hardening, GitHub Actions audits — without spending tokens until the tools are actually called.

```bash
# For Claude Code:
claude mcp add skillshield /path/to/skills-library/skills-mcp \
  -- --path /path/to/skills-library
```

Or hand-edit your client's MCP config:

```json
{
  "mcpServers": {
    "skillshield": {
      "command": "/path/to/skills-library/skills-mcp",
      "args": ["--path", "/path/to/skills-library"]
    }
  }
}
```

After restarting your client, ask the assistant something like *"scan this Dockerfile for hardening issues"* or *"is `event-stream@3.3.6` known malicious?"* — it'll route through the SkillShield tools.

## 4. Try a single tool call directly

You don't need an AI client to use `skills-mcp`. It speaks JSON-RPC 2.0 over stdio, so any script can drive it.

```bash
cd /path/to/skills-library

echo '{"jsonrpc":"2.0","id":1,"method":"tools/call",
  "params":{"name":"lookup_vulnerability",
    "arguments":{"package":"event-stream","ecosystem":"npm","version":"3.3.6"}}}' \
  | ./skills-mcp --path .
```

That returns the known compromise entry for the infamous 2018 supply-chain attack. Substitute any of the 15 tools listed in [`cmd/skills-mcp`](https://github.com/namncqualgo/skills-library/tree/main/cmd/skills-mcp).

!!! note "List all available tools"
    ```bash
    echo '{"jsonrpc":"2.0","id":1,"method":"tools/list"}' | ./skills-mcp --path .
    ```

## 5. Keep it current

Vulnerability data and detection patterns change weekly. Two refresh paths, decoupled:

```bash
# Refresh the committed library via signed manifest deltas (touches files in repo):
./skills-check update

# Populate the user-local OSV cache (~250 MB, ~80k npm advisories — no repo write):
./skills-check fetch-vulns --from-release
```

For unattended refresh, install the scheduler:

```bash
./skills-check scheduler install --interval 6h
```

That registers a `launchd` LaunchAgent (macOS), a `systemd` user timer (Linux), or a Task Scheduler task (Windows). No daemons, no privileged helpers.

## 6. Generate a compliance coverage report

```bash
./skills-check evidence --framework SOC2    --format markdown --out evidence-soc2.md
./skills-check evidence --framework HIPAA   --format json
./skills-check evidence --framework PCI-DSS --format markdown
```

Each report maps installed skills to framework controls with timestamps and source citations. The output is a developer-facing coverage map, not a substitute for a real audit.

## Next steps

- **Install on macOS / Linux / Windows** — see [install-macos](install-macos.md), [install-linux](install-linux.md), [install-windows](install-windows.md).
- **Rolling out to a team** — see [admin-team-rollout](admin-team-rollout.md).
- **Air-gapped / regulated environments** — see [air-gapped-install](air-gapped-install.md).
- **Architecture** — read [ARCHITECTURE.md](https://github.com/namncqualgo/skills-library/blob/main/ARCHITECTURE.md) for the full system design.
- **Signing model** — read [SIGNING.md](https://github.com/namncqualgo/skills-library/blob/main/SIGNING.md) for key custody and rotation.
