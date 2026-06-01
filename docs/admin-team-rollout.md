# Roll out secure-code to a team

This guide is for the engineering / security lead who wants every developer
on the team to have the same security rules injected into their AI coding
tool.

## 1. Pick the skill set

```bash
skills-check list --category prevention
skills-check list --category supply-chain
```

Decide which skill IDs you want to ship. A typical baseline is:
`secret-detection,dependency-audit,supply-chain-security,secure-code-review,api-security`.

## 2. Generate one IDE file per tool you support

Run `skills-check init` for each AI tool your team uses. The output is a
plain file that gets committed to your project.

```bash
skills-check init --tool claude   --skills "secret-detection,supply-chain-security,api-security" --budget compact
skills-check init --tool cursor   --skills "secret-detection,supply-chain-security,api-security" --budget compact
skills-check init --tool copilot  --skills "secret-detection,supply-chain-security,api-security" --budget compact
```

Commit the resulting `CLAUDE.md`, `.cursorrules`, and `copilot-instructions.md`
to the team's main repository.

## 3. Set up scheduled background updates on every workstation

Each developer runs once:

```bash
skills-check scheduler install
```

This installs an OS-native scheduled task (launchd / systemd timer / Task
Scheduler) that pulls signed updates every 6 hours and regenerates the IDE
files in place. No data leaves the workstation other than `GET` requests
for public release artifacts.

### Optional: live OSV enrichment on developer laptops

For teams whose developer workstations have outbound HTTPS to
`api.osv.dev`, launching `skills-mcp` with `--vuln-source hybrid` adds
a live-enrichment path on top of the scheduled fetch:

```bash
# Drop into the team-shared shell init (or claude/cursor MCP config)
skills-mcp --vuln-source hybrid
```

In hybrid mode, `lookup_vulnerability` / `check_dependency` query
`api.osv.dev` first (cached in-process for 5 minutes) and fall back to
the locally-fetched cache when the API is unreachable or returns no
data. The default remains `local` so air-gapped CI and regulated
workstations behave exactly as before.

Recommend hybrid for **developer laptops** (latest data while typing) and
keep `local` (with `fetch-vulns` scheduled) on **CI runners** so build
behaviour is deterministic and survives an osv.dev outage without
turning red. Internal package names should not appear on osv.dev under
either mode, but hybrid does emit each scanned package name to the API
— review with your legal / security team before enabling on any
machine that handles names you would not paste into a public search box.

## 4. Wire skills-check validate into CI

Add a job that asserts the committed IDE files match the current skills
set:

```yaml
- name: secure-code — validate
  run: |
    go install github.com/kennguy3n/skills-library/cmd/skills-check@latest
    skills-check validate
    skills-check regenerate --tool claude --out .
    git diff --exit-code CLAUDE.md
```

The same approach works for any other IDE file the team standardizes on.

## 5. Audit

Every developer runs `skills-check version` to print the embedded public
key ID. Compare against [`SIGNING.md`](../SIGNING.md) to confirm everyone
is verifying against the same release key.
