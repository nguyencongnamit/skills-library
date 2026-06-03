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
`scan_github_actions`, `scan_dockerfile`, `policy_check`) default to the
current working directory. To widen or pin the allow-list, pass through
flags after the package name:

```json
{ "command": "npx", "args": ["-y", "@namncqualgo/secure-code-mcp", "--allowed-roots", "/path/to/project"] }
```

## How it's packaged

This is a thin launcher. The server is a Go binary; this package declares one
optional dependency per platform (`-darwin-arm64`, `-linux-x64`, …) gated by
`os`/`cpu`, so npm installs **only** the binary for your machine — no
postinstall download, works offline and under `npm ci --ignore-scripts`. The
library data (skills, the OSV cache, checklists) ships once inside this
package and is handed to the binary via `--path`.

## Also available

- **Go:** `go install github.com/namncqualgo/skills-library/cmd/skills-mcp@latest`
  (then point `--path` at a library checkout or a `skills-check update` cache).
- **Binaries + data tarball:** attached to each
  [GitHub Release](https://github.com/namncqualgo/skills-library/releases).

## License

Apache-2.0. See the [repository](https://github.com/namncqualgo/skills-library).
