// CLI wrappers around the eight skills-mcp tools that operate on data
// or files: check-dependency, check-typosquat, lookup-vulnerability,
// scan-secrets, scan-dependencies, scan-dockerfile,
// scan-github-actions, and policy-check.
//
// These wrappers exist so contributors can drive the security tools
// from the terminal, shell scripts, and pre-commit hooks without
// having to speak JSON-RPC to skills-mcp. The shared Library code
// path means the CLI and MCP server produce identical findings —
// these subcommands are 100% thin adapters, not a second
// implementation.
//
// Three concerns are common across the eight subcommands and live in
// helpers here:
//
//   * library construction with --vuln-source threading, so the new
//     "hybrid OSV.dev enrichment" path is reachable from the terminal
//     the same way it is from MCP;
//   * file-based scan path sandboxing — every file-taking command
//     scopes the Library's allowed-roots to the file's parent so the
//     CLI inherits the same fail-safe sensitive-path deny-list the
//     MCP server uses;
//   * output formatting — text (default, human-readable) / json
//     (machine-readable, identical schema to the MCP response) /
//     sarif (CI ingestion).

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/namncqualgo/skills-library/internal/tools"
)

// supportedOutputFormats enumerates the values accepted by the
// --format flag on every subcommand. text is the human-readable
// default; json mirrors the MCP server's response payload (same
// types, same field names); sarif is only emitted for the
// subcommands whose Library counterpart already ships a SARIF
// transformer (the five *SARIF functions in cmd/skills-mcp/internal/
// tools/sarif*.go).
var supportedOutputFormats = map[string]bool{
	"text":  true,
	"json":  true,
	"sarif": true,
}

// newLibraryForCmd constructs a Library suitable for one CLI run.
// vulnSourceStr is parsed via tools.ParseVulnSource; an empty string
// resolves to SourceLocal, matching the skills-mcp default. fileArg,
// when non-empty, contributes its parent directory to the Library's
// allowed-roots so file-based scanners can read it without the user
// having to remember the security flag dance.
func newLibraryForCmd(repoPath, vulnSourceStr, fileArg string) (*tools.Library, error) {
	abs, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("resolve --path %q: %w", repoPath, err)
	}
	vulnSource, err := tools.ParseVulnSource(vulnSourceStr)
	if err != nil {
		return nil, err
	}
	opts := []tools.LibraryOption{tools.WithVulnSource(vulnSource)}
	lib, err := tools.NewLibrary(abs, opts...)
	if err != nil {
		return nil, err
	}
	if fileArg != "" {
		fileAbs, err := filepath.Abs(fileArg)
		if err != nil {
			return nil, fmt.Errorf("resolve file path %q: %w", fileArg, err)
		}
		if err := lib.SetAllowedRoots([]string{filepath.Dir(fileAbs)}); err != nil {
			return nil, fmt.Errorf("scope library to %s: %w", filepath.Dir(fileAbs), err)
		}
	}
	return lib, nil
}

// emitJSON writes obj as indented JSON. Used by every subcommand when
// the user asked for --format json or when text formatting is not
// supported for this result shape.
func emitJSON(w io.Writer, obj any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(obj)
}

// addVulnSourceFlag registers --vuln-source on a Cobra command,
// targeting *dst. The flag is only meaningful for the subcommands
// whose Library counterpart consults OSV; we register it on the
// commands that do (everything operating on packages or lockfiles)
// and omit it from the file-only scanners (secrets, dockerfile,
// github-actions, policy-check) where OSV is not consulted.
func addVulnSourceFlag(c *cobra.Command, dst *string) {
	c.Flags().StringVar(dst, "vuln-source", "local",
		"where OSV advisory lookups read from: 'local' (no network), 'external' (api.osv.dev), or 'hybrid' (external first, fall back to local). Default 'local' matches skills-mcp.")
}

// addFormatFlag registers --format on a Cobra command, validating
// against supportedOutputFormats. allowSARIF controls whether 'sarif'
// is an acceptable value — only the five subcommands whose Library
// has a SARIF transformer pass true.
func addFormatFlag(c *cobra.Command, dst *string, allowSARIF bool) {
	options := []string{"text", "json"}
	if allowSARIF {
		options = append(options, "sarif")
	}
	c.Flags().StringVar(dst, "format", "text",
		"output format: "+strings.Join(options, " | "))
}

// validateFormat rejects --format values the subcommand does not
// support. Done at the top of RunE so the failure mode is obvious
// before any library work happens.
func validateFormat(format string, allowSARIF bool) error {
	if !supportedOutputFormats[format] {
		return fmt.Errorf("unknown --format %q (want text, json%s)", format,
			ternary(allowSARIF, ", or sarif", ""))
	}
	if format == "sarif" && !allowSARIF {
		return fmt.Errorf("--format sarif is not supported for this command")
	}
	return nil
}

func ternary(cond bool, a, b string) string {
	if cond {
		return a
	}
	return b
}

// =============================================================================
// check-dependency
// =============================================================================

func checkDependencyCmd() *cobra.Command {
	var (
		repoPath, pkg, version, ecosystem, format, vulnSource string
	)
	c := &cobra.Command{
		Use:   "check-dependency",
		Short: "Check a package@version for known malicious entries, typosquats, CVE patterns, and OSV advisories",
		Long: `check-dependency wraps the skills-mcp check_dependency tool.

It looks up the named package in the malicious-packages corpus, the
typosquat database, the curated CVE-pattern list (ecosystem-language
filtered to avoid false matches like Java CVEs for an npm query), and
the OSV advisory set. With --vuln-source hybrid (or external), live
api.osv.dev results are merged in too.

Returns exit 0 always; the result still lists findings — use
'skills-check policy-check' when you need a CI-failing scan.`,
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			if strings.TrimSpace(pkg) == "" {
				return fmt.Errorf("--package is required")
			}
			if strings.TrimSpace(ecosystem) == "" {
				return fmt.Errorf("--ecosystem is required")
			}
			lib, err := newLibraryForCmd(repoPath, vulnSource, "")
			if err != nil {
				return err
			}
			res, err := lib.CheckDependency(pkg, version, ecosystem)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.CheckDependencySARIF(res))
			default:
				return renderCheckDependencyText(c.OutOrStdout(), res)
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the skills-library checkout")
	c.Flags().StringVarP(&pkg, "package", "p", "", "package name (required)")
	c.Flags().StringVarP(&version, "version", "v", "", "package version (optional; constrains OSV matching)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "package ecosystem: npm, pypi, crates, go, rubygems, maven, nuget, composer, pub, swift, github-actions, docker (required)")
	addFormatFlag(c, &format, true)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

func renderCheckDependencyText(w io.Writer, res *tools.CheckDependencyResult) error {
	fmt.Fprintf(w, "=== check-dependency %s@%s (%s) ===\n", res.Package, res.Version, res.Ecosystem)
	fmt.Fprintf(w, "Malicious entries:  %d\n", len(res.Malicious))
	fmt.Fprintf(w, "Typosquat matches:  %d\n", len(res.Typosquats))
	fmt.Fprintf(w, "CVE pattern hits:   %d\n", len(res.CVEs))
	fmt.Fprintf(w, "OSV advisories:     %d\n", len(res.OSVAdvisories))
	for _, m := range res.Malicious {
		fmt.Fprintf(w, "  ! MALICIOUS  [%s]  %s — %s\n", m.Severity, m.Name, m.Description)
	}
	for _, t := range res.Typosquats {
		fmt.Fprintf(w, "  ! TYPOSQUAT  of %s (distance %d, %s)\n", t.Target, t.LevenshteinDistance, t.Status)
	}
	for _, cve := range res.CVEs {
		fmt.Fprintf(w, "  ! CVE        [%s]  %s — %s\n", cve.Severity, cve.CVE, cve.Name)
	}
	for _, a := range res.OSVAdvisories {
		fmt.Fprintf(w, "  ! OSV        [%s]  %s — %s\n", a.Severity, a.ID, a.Summary)
	}
	return nil
}

// =============================================================================
// check-typosquat
// =============================================================================

func checkTyposquatCmd() *cobra.Command {
	var repoPath, pkg, ecosystem, format string
	c := &cobra.Command{
		Use:   "check-typosquat",
		Short: "Flag candidate typosquats against the curated DB plus a Levenshtein-2 sweep over popular packages",
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			if strings.TrimSpace(pkg) == "" {
				return fmt.Errorf("--package is required")
			}
			lib, err := newLibraryForCmd(repoPath, "", "")
			if err != nil {
				return err
			}
			res, err := lib.CheckTyposquat(pkg, ecosystem)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== check-typosquat %s (%s) ===\n", res.Package, res.Ecosystem)
				fmt.Fprintf(c.OutOrStdout(), "Curated DB matches:        %d\n", len(res.Typosquats))
				fmt.Fprintf(c.OutOrStdout(), "Runtime Levenshtein hits:  %d\n", len(res.PotentialTyposquats))
				for _, t := range res.Typosquats {
					fmt.Fprintf(c.OutOrStdout(), "  ! curated: target=%s squat=%s ecosystem=%s status=%s\n", t.Target, t.Typosquat, t.Ecosystem, t.Status)
				}
				for _, p := range res.PotentialTyposquats {
					fmt.Fprintf(c.OutOrStdout(), "  ? potential: target=%s ecosystem=%s distance=%d confidence=%s\n", p.Target, p.Ecosystem, p.Distance, p.Confidence)
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the skills-library checkout")
	c.Flags().StringVarP(&pkg, "package", "p", "", "package name to check (required)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "package ecosystem (optional; empty searches all)")
	addFormatFlag(c, &format, false)
	return c
}

// =============================================================================
// lookup-vulnerability
// =============================================================================

func lookupVulnerabilityCmd() *cobra.Command {
	var repoPath, pkg, ecosystem, version, format, vulnSource string
	c := &cobra.Command{
		Use:   "lookup-vulnerability",
		Short: "Search the supply-chain malicious-packages corpus + OSV advisories for a package",
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			if strings.TrimSpace(pkg) == "" {
				return fmt.Errorf("--package is required")
			}
			lib, err := newLibraryForCmd(repoPath, vulnSource, "")
			if err != nil {
				return err
			}
			res, err := lib.LookupVulnerability(pkg, ecosystem, version)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== lookup-vulnerability %s (%s) ===\n", res.Package, res.Ecosystem)
				fmt.Fprintf(c.OutOrStdout(), "Malicious matches:  %d\n", len(res.Matches))
				fmt.Fprintf(c.OutOrStdout(), "Typosquat matches:  %d\n", len(res.Typosquats))
				fmt.Fprintf(c.OutOrStdout(), "OSV advisories:     %d\n", len(res.OSVAdvisories))
				for _, m := range res.Matches {
					fmt.Fprintf(c.OutOrStdout(), "  ! [%s] %s — %s\n", m.Severity, m.Name, m.Description)
				}
				for _, a := range res.OSVAdvisories {
					fmt.Fprintf(c.OutOrStdout(), "  ! OSV [%s] %s — %s\n", a.Severity, a.ID, a.Summary)
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the skills-library checkout")
	c.Flags().StringVarP(&pkg, "package", "p", "", "package name (required)")
	c.Flags().StringVarP(&ecosystem, "ecosystem", "e", "", "ecosystem (optional; empty searches all)")
	c.Flags().StringVarP(&version, "version", "v", "", "version (optional)")
	addFormatFlag(c, &format, false)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

// =============================================================================
// scan-secrets
// =============================================================================

func scanSecretsCmd() *cobra.Command {
	var repoPath, format string
	c := &cobra.Command{
		Use:   "scan-secrets <file>",
		Short: "DLP-style scan of a file for credentials, API keys, tokens, and PEM material",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			file := args[0]
			lib, err := newLibraryForCmd(repoPath, "", file)
			if err != nil {
				return err
			}
			fileAbs, _ := filepath.Abs(file)
			res, err := lib.ScanSecrets("", fileAbs)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.ScanSecretsSARIF(res))
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== scan-secrets %s ===\n", file)
				fmt.Fprintf(c.OutOrStdout(), "Matches: %d\n", len(res.Matches))
				for _, m := range res.Matches {
					kfp := ""
					if m.KnownFalsePositive {
						kfp = "  (known-FP)"
					}
					fmt.Fprintf(c.OutOrStdout(), "  ! [%s] %s at offset %d-%d%s\n",
						m.Severity, m.Name, m.Start, m.End, kfp)
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the skills-library checkout (for rule data)")
	addFormatFlag(c, &format, true)
	return c
}

// =============================================================================
// scan-dependencies
// =============================================================================

func scanDependenciesCmd() *cobra.Command {
	var repoPath, format, vulnSource string
	c := &cobra.Command{
		Use:   "scan-dependencies <lockfile>",
		Short: "Parse a lockfile and check every resolved (name, version) against malicious / typosquat / CVE / OSV databases",
		Long: `Supported lockfiles: package-lock.json, yarn.lock, pnpm-lock.yaml,
requirements.txt, Pipfile.lock, poetry.lock, go.sum, Cargo.lock,
pom.xml, gradle.lockfile, packages.lock.json, *.csproj / *.fsproj /
*.vbproj, and Gemfile.lock.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			file := args[0]
			lib, err := newLibraryForCmd(repoPath, vulnSource, file)
			if err != nil {
				return err
			}
			fileAbs, _ := filepath.Abs(file)
			res, err := lib.ScanDependencies(fileAbs)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.ScanDependenciesSARIF(res))
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== scan-dependencies %s ===\n", file)
				fmt.Fprintf(c.OutOrStdout(), "Dependencies parsed: %d  ecosystem=%s\n", res.Dependencies, res.Ecosystem)
				fmt.Fprintf(c.OutOrStdout(), "Findings: %d\n", len(res.Findings))
				for _, f := range res.Findings {
					fmt.Fprintf(c.OutOrStdout(), "  ! [%s] %s@%s — %s: %s\n",
						f.Severity, f.Package, f.Version, f.Category, f.Message)
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the skills-library checkout")
	addFormatFlag(c, &format, true)
	addVulnSourceFlag(c, &vulnSource)
	return c
}

// =============================================================================
// scan-dockerfile
// =============================================================================

func scanDockerfileCmd() *cobra.Command {
	var repoPath, format string
	c := &cobra.Command{
		Use:   "scan-dockerfile <Dockerfile>",
		Short: "Hardening pass over a Dockerfile (USER root, unpinned base, ADD remote, curl|sh, secrets in env, etc.)",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			file := args[0]
			lib, err := newLibraryForCmd(repoPath, "", file)
			if err != nil {
				return err
			}
			fileAbs, _ := filepath.Abs(file)
			res, err := lib.ScanDockerfile(fileAbs)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.ScanDockerfileSARIF(res))
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== scan-dockerfile %s ===\n", file)
				fmt.Fprintf(c.OutOrStdout(), "Findings: %d\n", len(res.Findings))
				for _, f := range res.Findings {
					fmt.Fprintf(c.OutOrStdout(), "  ! [%s] %s:%d  %s\n", f.Severity, f.RuleID, f.Line, f.Title)
					if f.Fix != "" {
						fmt.Fprintf(c.OutOrStdout(), "        fix: %s\n", f.Fix)
					}
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the skills-library checkout")
	addFormatFlag(c, &format, true)
	return c
}

// =============================================================================
// scan-github-actions
// =============================================================================

func scanGitHubActionsCmd() *cobra.Command {
	var repoPath, format string
	c := &cobra.Command{
		Use:   "scan-github-actions <workflow.yml>",
		Short: "Lint a GitHub Actions workflow for pwn-request, script-injection, unpinned actions, missing permissions, and credential exposure",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			file := args[0]
			lib, err := newLibraryForCmd(repoPath, "", file)
			if err != nil {
				return err
			}
			fileAbs, _ := filepath.Abs(file)
			res, err := lib.ScanGitHubActions(fileAbs)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.ScanGitHubActionsSARIF(res))
			default:
				fmt.Fprintf(c.OutOrStdout(), "=== scan-github-actions %s ===\n", file)
				fmt.Fprintf(c.OutOrStdout(), "Findings: %d\n", len(res.Findings))
				for _, f := range res.Findings {
					fmt.Fprintf(c.OutOrStdout(), "  ! [%s] %s  (line %d) — %s\n", f.Severity, f.RuleID, f.Line, f.Title)
					if f.Fix != "" {
						fmt.Fprintf(c.OutOrStdout(), "        fix: %s\n", f.Fix)
					}
				}
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the skills-library checkout")
	addFormatFlag(c, &format, true)
	return c
}

// =============================================================================
// policy-check
// =============================================================================

func policyCheckCmd() *cobra.Command {
	var repoPath, severityFloor, format string
	c := &cobra.Command{
		Use:   "policy-check <file>",
		Short: "Dispatch the appropriate scanner for <file> and exit non-zero when any finding meets the severity floor",
		Long: `policy-check chooses between scan-dependencies / scan-dockerfile /
scan-github-actions / scan-secrets based on the input file shape and
returns a CI-friendly exit code: 0 when nothing meets the severity
floor, 1 when at least one finding does. severity-floor defaults to
"high".

This is the canonical "fail the build" CLI entry point. Wrap it in a
shell call from your pre-commit or CI step.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			file := args[0]
			lib, err := newLibraryForCmd(repoPath, "", file)
			if err != nil {
				return err
			}
			fileAbs, _ := filepath.Abs(file)
			res, err := lib.PolicyCheck(fileAbs, severityFloor)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				_ = emitJSON(c.OutOrStdout(), res)
			default:
				verdict := "PASS"
				if !res.Pass {
					verdict = "FAIL"
				}
				fmt.Fprintf(c.OutOrStdout(), "=== policy-check %s ===\n", file)
				fmt.Fprintf(c.OutOrStdout(), "Verdict:        %s\n", verdict)
				fmt.Fprintf(c.OutOrStdout(), "Severity floor: %s\n", res.SeverityFloor)
				fmt.Fprintf(c.OutOrStdout(), "Scanner used:   %s\n", res.Scan)
				fmt.Fprintf(c.OutOrStdout(), "Findings: %d\n", len(res.Findings))
				for sev, n := range res.Counts {
					fmt.Fprintf(c.OutOrStdout(), "  %s: %d\n", sev, n)
				}
			}
			// Surface the result via exit code so a CI step can gate
			// on a single command. We return a sentinel error here
			// rather than os.Exit so the Cobra layer can still print
			// any final state and tests can observe the failure.
			if !res.Pass {
				// Hide usage on a policy failure — this is not a
				// flag-error, just findings.
				c.SilenceUsage = true
				return &policyFailureError{count: len(res.Findings), floor: res.SeverityFloor}
			}
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "path to the skills-library checkout")
	c.Flags().StringVar(&severityFloor, "severity-floor", "high",
		"the lowest severity that causes a non-zero exit: critical | high | medium | low")
	addFormatFlag(c, &format, false)
	return c
}

// policyFailureError is the sentinel returned by policy-check when at
// least one finding meets the severity floor. We give it a dedicated
// type so the binary's top-level error handler (cmd.Execute in
// main.go) can convert it to a non-zero exit without dumping the
// flag-usage block to stderr.
type policyFailureError struct {
	count int
	floor string
}

func (e *policyFailureError) Error() string {
	return fmt.Sprintf("policy-check: %d finding(s) at or above %s", e.count, e.floor)
}

// IsPolicyFailure reports whether err is the sentinel above. Used by
// callers that want to distinguish "the policy check returned
// findings" from "the policy check itself errored". Exported so
// outboard test harnesses can branch on it without relying on
// errors.As against an unexported type.
func IsPolicyFailure(err error) bool {
	_, ok := err.(*policyFailureError)
	return ok
}
