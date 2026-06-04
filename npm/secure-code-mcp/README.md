# @namncqualgo/secure-code-mcp

The **secure-code** security skills server, speaking the [Model Context
Protocol](https://modelcontextprotocol.io) over stdio. Point your AI coding
agent at it to get secret detection, dependency / CVE scanning (offline OSV
cache), Dockerfile & GitHub Actions hardening checks, and 28 security skills.

## Use it

No global install needed — reference it with `npx` in your MCP client config.

**Claude Code / Claude Desktop / Cursor** (`mcpServers` block):

```json
{
  "mcpServers": {
    "secure-code": {
      "command": "npx",
      "args": ["-y", "@namncqualgo/secure-code-mcp"]
    }
  }
}
```

That's it. On first run npm fetches the package plus the one prebuilt server
binary matching your OS/CPU.

### Restricting file access

The file-reading tools (`scan_secrets`, `scan_dependencies`,
`scan_github_actions`, `scan_dockerfile`, `gate`) default to the
current working directory. To widen or pin the allow-list, pass through
flags after the package name:

```json
{ "command": "npx", "args": ["-y", "@namncqualgo/secure-code-mcp", "--allowed-roots", "/path/to/project"] }
```

## CLI — `secure-code-check` (the gate)

The same package also ships the `skills-check` CLI as a second command,
`secure-code-check`, for use in scripts, pre-commit hooks, and CI — no
JSON-RPC, just an exit code:

```bash
npm i -D @namncqualgo/secure-code-mcp
# pick the right scanner for a file and fail (exit 1) on findings >= floor
npx -p @namncqualgo/secure-code-mcp secure-code-check gate Dockerfile --severity-floor high
```

`gate` dispatches to the dependency / Dockerfile / GitHub Actions scanners by
file shape and falls back to a secret scan for anything else. The bundled
data tree is located automatically (no `--path` needed).

## How it's packaged

This is a thin launcher. The server and CLI are Go binaries; this package
declares one optional dependency per platform (`-darwin-arm64`, `-linux-x64`,
…) gated by `os`/`cpu`, so npm installs **only** the binaries for your machine
— no postinstall download, works offline and under `npm ci --ignore-scripts`.
The library data (skills, the OSV cache, checklists) ships once inside this
package and is shared by both bins (`secure-code-mcp` via `--path`,
`secure-code-check` via `$SKILLS_LIBRARY_PATH`).

## Also available

- **Go:** `go install github.com/namncqualgo/skills-library/cmd/skills-mcp@latest`
  (then point `--path` at a library checkout or a `skills-check update` cache).
- **Binaries + data tarball:** attached to each
  [GitHub Release](https://github.com/namncqualgo/skills-library/releases).

## License

Apache-2.0. See the [repository](https://github.com/namncqualgo/skills-library).
