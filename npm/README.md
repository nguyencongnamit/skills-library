# npm packaging for `skills-mcp`

This directory packages the Go MCP server (`cmd/skills-mcp`) for distribution
over npm, so users can run it with `npx @namncqualgo/secure-code-mcp` — the
de-facto convention for MCP servers in Claude Code / Cursor / etc.

## Layout

```
npm/
  secure-code-mcp/        source skeleton of the MAIN (platform-agnostic) package
    bin/launch.js         the launcher (resolves the host binary, execs it with --path)
    package.json          version "0.0.0-dev" placeholder; optionalDependencies listed
    README.md             user-facing npm readme
  build.mjs               generator: binaries + data tree -> publishable package set
  smoke-test.mjs          host-only end-to-end test (build -> assemble -> initialize handshake)
  dist/                   (generated, git-ignored) the assembled packages
```

## Distribution model (esbuild-style platform packages)

`npx` runs a **thin launcher**, not the Go binary directly. The published set is:

- **`@namncqualgo/secure-code-mcp`** — platform-agnostic. Ships `bin/launch.js`
  plus the **library data tree** (`data/`: skills, the OSV cache, checklists —
  ~10 MB, shipped once). Lists all five platform packages as
  `optionalDependencies`.
- **`@namncqualgo/secure-code-mcp-<os>-<arch>`** ×5 — each carries only the
  prebuilt `skills-mcp` binary, gated by `os`/`cpu`.

Because the binaries are `optionalDependencies` gated by `os`/`cpu`, npm
installs **only the one** matching the host. There is **no postinstall
download** — installs work offline and under `npm ci --ignore-scripts`, which
matters for a security tool (no arbitrary fetch-and-exec at install time).

`launch.js` resolves the host platform package via
`require.resolve('@namncqualgo/secure-code-mcp-<key>/package.json')`, then
spawns its `skills-mcp` binary with `--path <this package>/data` and forwards
argv + stdio. skills-mcp reads its data from disk (it does not `go:embed`), so
the data must travel with it — hence the bundled `data/`.

### Why not a single self-contained binary (`go:embed`)?

Embedding would freeze the data at build time and bypass the
`skills-check update` model that refreshes the OSV cache independently of the
binary. Shipping data-as-files keeps that property and adds no Go changes.

## Build

```sh
# from release artifacts (CI) or locally cross-compiled binaries:
node npm/build.mjs --binaries <dir-of-skills-mcp-binaries> --root . --version <x.y.z> --out npm/dist
```

`--binaries` must contain `skills-mcp-<goos>-<goarch>[.exe]` (the names
`release.yml` produces). Missing platforms are skipped with a warning and
dropped from the main package's `optionalDependencies`, so a single-platform
assembly is valid for local testing.

## Test

```sh
node npm/smoke-test.mjs
```

Builds `skills-mcp` for the host, assembles the main + host platform package,
wires the platform package into the main package's `node_modules` (what npm
would do via the optionalDependency), launches `bin/launch.js`, and asserts the
MCP `initialize` handshake returns `serverInfo.name === "skills-mcp"`. No
network, no registry.

## Publishing

Not done here. The `npm publish --provenance` workflow (added separately) runs
`build.mjs` against the release binaries, runs `smoke-test.mjs` as a gate, and
publishes all six packages at the release version. Requires the `@namncqualgo`
npm scope and an `NPM_TOKEN` repo secret.
