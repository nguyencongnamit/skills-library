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
	"os"
	"path/filepath"
	"sort"
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

// resolveLibraryRoot picks the skills-library checkout the file
// scanners read their rule data from. Precedence:
//
//  1. an explicit --path (anything other than the "." default);
//  2. $SKILLS_LIBRARY_PATH, so the CLI can run inside an arbitrary
//     project (CI, pre-commit, a hook) while pointed at a bundled data
//     tree — mirroring how cmd/skills-mcp resolves its own root;
//  3. the current working directory ("."), the in-repo contributor
//     default.
//
// Treating the "." default the same as "unset" is deliberate: a bare
// `skills-check scan-dockerfile Dockerfile` run from a user's project
// should fall through to the env, not fail because that project has no
// skills/ tree of its own.
func resolveLibraryRoot(flagVal string) string {
	if flagVal != "" && flagVal != "." {
		return flagVal
	}
	if env := strings.TrimSpace(os.Getenv("SKILLS_LIBRARY_PATH")); env != "" {
		return env
	}
	if flagVal == "" {
		return "."
	}
	return flagVal
}

// newLibraryForCmd constructs a Library suitable for one CLI run.
// vulnSourceStr is parsed via tools.ParseVulnSource; an empty string
// resolves to SourceLocal, matching the skills-mcp default. fileArg,
// when non-empty, contributes its parent directory to the Library's
// allowed-roots so file-based scanners can read it without the user
// having to remember the security flag dance.
func newLibraryForCmd(repoPath, vulnSourceStr, fileArg string) (*tools.Library, error) {
	root := resolveLibraryRoot(repoPath)
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve --path %q: %w", root, err)
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
'skills-check gate' when you need a CI-failing scan.`,
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
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
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
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
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
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
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
	var repoPath, format, report string
	c := &cobra.Command{
		Use:   "scan-secrets <file-or-dir>",
		Short: "DLP-style scan of a file (or, recursively, a directory of text files) for credentials, API keys, tokens, and PEM material",
		Long: `DLP-style scan of a file, or recursively of a directory of text
files, for credentials, API keys, tokens, and PEM material.

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			target := args[0]
			lib, err := newLibraryForCmd(repoPath, "", target)
			if err != nil {
				return err
			}
			targetAbs, _ := filepath.Abs(target)
			info, err := os.Stat(targetAbs)
			if err != nil {
				return fmt.Errorf("scan-secrets: stat %s: %w", target, err)
			}

			// Single file: behaviour is unchanged from the original
			// implementation (label echoes the raw argument).
			if !info.IsDir() {
				res, err := lib.ScanSecrets("", targetAbs)
				if err != nil {
					return err
				}
				if report != "" {
					rep := newReport("scan-secrets", []string{target})
					rep.Sections = append(rep.Sections, secretSection(target, res))
					return writeReport(c, report, rep)
				}
				switch format {
				case "json":
					return emitJSON(c.OutOrStdout(), res)
				case "sarif":
					return emitJSON(c.OutOrStdout(), tools.ScanSecretsSARIF(res))
				default:
					printScanSecretsText(c.OutOrStdout(), target, res)
					return nil
				}
			}

			// Directory: scope the allow-list to the directory itself so
			// every descendant passes validateScanPath, then walk it and
			// scan each text file. Per-file ScanSecrets calls keep their
			// full policy enforcement (size cap, sensitive-path deny-list,
			// symlink resolution); files that fail are reported on stderr
			// and skipped so one bad file never aborts the whole scan.
			if err := lib.SetAllowedRoots([]string{targetAbs}); err != nil {
				return fmt.Errorf("scan-secrets: scope library to %s: %w", targetAbs, err)
			}
			results, err := scanSecretsDir(c, lib, targetAbs)
			if err != nil {
				return err
			}
			if report != "" {
				rep := newReport("scan-secrets", []string{target})
				for _, res := range results {
					rep.Sections = append(rep.Sections, secretSection(res.FilePath, res))
				}
				return writeReport(c, report, rep)
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), results)
			case "sarif":
				log := &tools.SARIFLog{
					Schema:  tools.SARIFSchema,
					Version: tools.SARIFVersion,
					Runs:    []tools.SARIFRun{},
				}
				for _, res := range results {
					log.Runs = append(log.Runs, tools.ScanSecretsSARIF(res).Runs...)
				}
				return emitJSON(c.OutOrStdout(), log)
			default:
				// Only files with matches are printed; clean files would
				// just be noise across a large tree. The summary still
				// reports the full count scanned.
				total := 0
				for _, res := range results {
					if len(res.Matches) == 0 {
						continue
					}
					printScanSecretsText(c.OutOrStdout(), res.FilePath, res)
					total += len(res.Matches)
				}
				fmt.Fprintf(c.OutOrStdout(), "Scanned %d text file(s); %d match(es) total\n",
					len(results), total)
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout for rule data (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	return c
}

// printScanSecretsText renders one ScanSecretsResult in the
// human-readable --format text shape. Extracted so the single-file
// and directory code paths emit byte-identical per-file output.
func printScanSecretsText(w io.Writer, label string, res *tools.ScanSecretsResult) {
	fmt.Fprintf(w, "=== scan-secrets %s ===\n", label)
	fmt.Fprintf(w, "Matches: %d\n", len(res.Matches))
	for _, m := range res.Matches {
		kfp := ""
		if m.KnownFalsePositive {
			kfp = "  (known-FP)"
		}
		fmt.Fprintf(w, "  ! [%s] %s at offset %d-%d%s\n",
			m.Severity, m.Name, m.Start, m.End, kfp)
	}
}

// scanSecretsDir runs ScanSecrets on every text file beneath dir,
// discovered via the shared tools.WalkScanFiles walker (noise dirs,
// non-regular entries, and empty/oversized/binary files are pruned
// there). Per-file scan errors — e.g. a path inside a sensitive
// directory — are reported on stderr and skipped rather than aborting.
func scanSecretsDir(c *cobra.Command, lib *tools.Library, dir string) ([]*tools.ScanSecretsResult, error) {
	files, err := tools.WalkScanFiles(dir, nil)
	if err != nil {
		return nil, fmt.Errorf("scan-secrets: walk %s: %w", dir, err)
	}
	results := make([]*tools.ScanSecretsResult, 0, len(files))
	for _, path := range files {
		res, err := lib.ScanSecrets("", path)
		if err != nil {
			fmt.Fprintf(c.ErrOrStderr(), "scan-secrets: skip %s: %v\n", path, err)
			continue
		}
		results = append(results, res)
	}
	return results, nil
}

// =============================================================================
// scan-dependencies
// =============================================================================

func scanDependenciesCmd() *cobra.Command {
	var repoPath, format, vulnSource, report string
	c := &cobra.Command{
		Use:   "scan-dependencies <lockfile-or-dir>",
		Short: "Parse a lockfile (or auto-discover lockfiles under a directory) and check every resolved (name, version) against malicious / typosquat / CVE / OSV databases",
		Long: `Supported lockfiles: package-lock.json, npm-shrinkwrap.json,
yarn.lock, pnpm-lock.yaml, requirements*.txt, Pipfile.lock,
poetry.lock, go.sum, Cargo.lock, pom.xml, gradle.lockfile,
build.gradle.lockfile, packages.lock.json, *.csproj / *.fsproj /
*.vbproj, and Gemfile.lock.

Pass a single lockfile to scan just that file, or a directory to
auto-discover and scan every recognised lockfile beneath it
(node_modules, vendor, and .git are skipped). Scanning a directory
with no recognised lockfile is an error.

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			target := args[0]
			lib, err := newLibraryForCmd(repoPath, vulnSource, target)
			if err != nil {
				return err
			}
			targetAbs, _ := filepath.Abs(target)
			info, err := os.Stat(targetAbs)
			if err != nil {
				return fmt.Errorf("scan-dependencies: stat %s: %w", target, err)
			}

			// Single lockfile: behaviour is unchanged.
			if !info.IsDir() {
				res, err := lib.ScanDependencies(targetAbs)
				if err != nil {
					return err
				}
				if report != "" {
					rep := newReport("scan-dependencies", []string{target})
					rep.Sections = append(rep.Sections, dependencySection(res))
					return writeReport(c, report, rep)
				}
				switch format {
				case "json":
					return emitJSON(c.OutOrStdout(), res)
				case "sarif":
					return emitJSON(c.OutOrStdout(), tools.ScanDependenciesSARIF(res))
				default:
					printScanDependenciesText(c.OutOrStdout(), target, res)
					return nil
				}
			}

			// Directory: scope the allow-list to the directory and
			// auto-discover every recognised lockfile beneath it.
			if err := lib.SetAllowedRoots([]string{targetAbs}); err != nil {
				return fmt.Errorf("scan-dependencies: scope library to %s: %w", targetAbs, err)
			}
			lockfiles, err := discoverLockfiles(targetAbs)
			if err != nil {
				return err
			}
			if len(lockfiles) == 0 {
				return fmt.Errorf("scan-dependencies: no recognised lockfile found under %s", target)
			}
			results := make([]*tools.ScanDependenciesResult, 0, len(lockfiles))
			for _, lf := range lockfiles {
				res, err := lib.ScanDependencies(lf)
				if err != nil {
					fmt.Fprintf(c.ErrOrStderr(), "scan-dependencies: skip %s: %v\n", lf, err)
					continue
				}
				results = append(results, res)
			}
			if report != "" {
				rep := newReport("scan-dependencies", []string{target})
				for _, res := range results {
					rep.Sections = append(rep.Sections, dependencySection(res))
				}
				return writeReport(c, report, rep)
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), results)
			case "sarif":
				log := &tools.SARIFLog{
					Schema:  tools.SARIFSchema,
					Version: tools.SARIFVersion,
					Runs:    []tools.SARIFRun{},
				}
				for _, res := range results {
					log.Runs = append(log.Runs, tools.ScanDependenciesSARIF(res).Runs...)
				}
				return emitJSON(c.OutOrStdout(), log)
			default:
				// Only lockfiles with findings are printed; clean ones are
				// omitted. The summary still reports the full count scanned.
				totalFindings := 0
				for _, res := range results {
					if len(res.Findings) == 0 {
						continue
					}
					printScanDependenciesText(c.OutOrStdout(), res.FilePath, res)
					totalFindings += len(res.Findings)
				}
				fmt.Fprintf(c.OutOrStdout(), "Scanned %d lockfile(s); %d finding(s) total\n",
					len(results), totalFindings)
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addVulnSourceFlag(c, &vulnSource)
	addReportFlag(c, &report)
	return c
}

// printScanDependenciesText renders one ScanDependenciesResult in the
// human-readable --format text shape. Extracted so the single-file and
// directory code paths emit byte-identical per-lockfile output.
func printScanDependenciesText(w io.Writer, label string, res *tools.ScanDependenciesResult) {
	fmt.Fprintf(w, "=== scan-dependencies %s ===\n", label)
	fmt.Fprintf(w, "Dependencies parsed: %d  ecosystem=%s\n", res.Dependencies, res.Ecosystem)
	fmt.Fprintf(w, "Findings: %d\n", len(res.Findings))
	for _, f := range res.Findings {
		fmt.Fprintf(w, "  ! [%s] %s@%s — %s: %s\n",
			f.Severity, f.Package, f.Version, f.Category, f.Message)
	}
}

// discoverLockfiles returns the paths of every recognised dependency
// lockfile beneath dir, via the shared tools.WalkScanFiles walker. The
// keep predicate narrows the walk to known lockfile names; the walker
// handles the noise-dir pruning (node_modules, vendor, build output, …)
// and the non-regular / oversized / binary skips so a project's own
// manifests are scanned without descending into installed-dependency
// trees.
func discoverLockfiles(dir string) ([]string, error) {
	return tools.DiscoverLockfiles(dir)
}

// =============================================================================
// scan-dockerfile
// =============================================================================

func scanDockerfileCmd() *cobra.Command {
	var repoPath, format, report string
	c := &cobra.Command{
		Use:   "scan-dockerfile <Dockerfile>",
		Short: "Hardening pass over a Dockerfile (USER root, unpinned base, ADD remote, curl|sh, secrets in env, etc.)",
		Long: `Hardening pass over a Dockerfile (USER root, unpinned base, ADD
remote, curl|sh, secrets in env, etc.).

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
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
			if report != "" {
				rep := newReport("scan-dockerfile", []string{file})
				rep.Sections = append(rep.Sections, dockerfileSection(file, res))
				return writeReport(c, report, rep)
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
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	return c
}

// =============================================================================
// scan-github-actions
// =============================================================================

func scanGitHubActionsCmd() *cobra.Command {
	var repoPath, format, report string
	c := &cobra.Command{
		Use:   "scan-github-actions <workflow.yml>",
		Short: "Lint a GitHub Actions workflow for pwn-request, script-injection, unpinned actions, missing permissions, and credential exposure",
		Long: `Lint a GitHub Actions workflow for pwn-request, script-injection,
unpinned actions, missing permissions, and credential exposure.

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
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
			if report != "" {
				rep := newReport("scan-github-actions", []string{file})
				rep.Sections = append(rep.Sections, githubActionsSection(file, res))
				return writeReport(c, report, rep)
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
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	return c
}

// =============================================================================
// scan-iac
// =============================================================================

func scanIaCCmd() *cobra.Command {
	var repoPath, format, report string
	c := &cobra.Command{
		Use:   "scan-iac <file>",
		Short: "Hardening pass over a Terraform / Kubernetes / CloudFormation file (public ingress, hard-coded creds, IAM wildcards, privileged/root containers, host namespaces, disabled encryption)",
		Long: `Hardening pass over an Infrastructure-as-Code file. The dialect
(Terraform .tf, a Kubernetes manifest, or an AWS CloudFormation
template) is detected from the path and content; a file that is not
recognised IaC reports no findings.

` + reportHelpParagraph,
		Args: cobra.ExactArgs(1),
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
			res, err := lib.ScanIaC(fileAbs)
			if err != nil {
				return err
			}
			if report != "" {
				rep := newReport("scan-iac", []string{file})
				rep.Sections = append(rep.Sections, iacSection(file, res))
				return writeReport(c, report, rep)
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), res)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.ScanIaCSARIF(res))
			default:
				kind := string(res.Kind)
				if kind == "" {
					kind = "not recognised as IaC"
				}
				fmt.Fprintf(c.OutOrStdout(), "=== scan-iac %s (%s) ===\n", file, kind)
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
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
	return c
}

// =============================================================================
// sbom
// =============================================================================

func sbomCmd() *cobra.Command {
	var repoPath, format string
	c := &cobra.Command{
		Use:   "sbom [dir]",
		Short: "Generate a CycloneDX 1.5 software bill of materials from a project's dependency lockfiles",
		Long: `Discover every recognised lockfile under the target directory
(default: the current directory), parse each into its resolved
(name, version, ecosystem) tuples, de-duplicate, and emit a
CycloneDX 1.5 SBOM. The component inventory is exactly the set of
packages scan-dependencies evaluates — one resolution path, so the
BOM never drifts from what the scanner sees.

Generation is pure and deterministic (no network, no timestamp): the
same tree always yields byte-identical output, so the BOM stays
diffable in CI. Use --format json for the CycloneDX document itself
(the artifact to commit); the default text format prints a
per-ecosystem component summary. This is the real artifact the EU CRA
Annex I (2)(1) "draw up a software bill of materials" obligation asks
for.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			target := "."
			if len(args) == 1 {
				target = args[0]
			}
			lib, err := newLibraryForCmd(repoPath, "", target)
			if err != nil {
				return err
			}
			targetAbs, _ := filepath.Abs(target)
			info, err := os.Stat(targetAbs)
			if err != nil {
				return fmt.Errorf("sbom: stat %s: %w", target, err)
			}
			// A directory target inventories every lockfile beneath it; a
			// single lockfile target inventories only that file (so e.g.
			// `sbom go.sum` describes the project's own deps, not sibling
			// fixtures). Either way the allow-list is scoped to the directory
			// so readScanFile permits the reads.
			allowRoot := targetAbs
			if !info.IsDir() {
				allowRoot = filepath.Dir(targetAbs)
			}
			if err := lib.SetAllowedRoots([]string{allowRoot}); err != nil {
				return fmt.Errorf("sbom: scope library to %s: %w", allowRoot, err)
			}
			bom, err := lib.GenerateSBOM(targetAbs)
			if err != nil {
				return err
			}
			if format == "json" {
				return emitJSON(c.OutOrStdout(), bom)
			}
			printSBOMText(c.OutOrStdout(), bom)
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, false)
	return c
}

// printSBOMText renders a human summary of a generated BOM: the subject,
// the total component count, and a per-ecosystem breakdown in stable
// (alphabetical) order. The CycloneDX document itself is emitted only
// under --format json.
func printSBOMText(w io.Writer, bom *tools.SBOM) {
	subject := "project"
	if bom.Metadata.Component != nil && bom.Metadata.Component.Name != "" {
		subject = bom.Metadata.Component.Name
	}
	fmt.Fprintf(w, "=== sbom %s (CycloneDX %s) ===\n", subject, bom.SpecVersion)
	fmt.Fprintf(w, "Components: %d\n", len(bom.Components))
	counts := map[string]int{}
	for _, comp := range bom.Components {
		eco := comp.Ecosystem
		if eco == "" {
			eco = "(unknown)"
		}
		counts[eco]++
	}
	ecos := make([]string, 0, len(counts))
	for eco := range counts {
		ecos = append(ecos, eco)
	}
	sort.Strings(ecos)
	for _, eco := range ecos {
		fmt.Fprintf(w, "  %-10s %d\n", eco, counts[eco])
	}
}

// =============================================================================
// scan-reachability
// =============================================================================

func scanReachabilityCmd() *cobra.Command {
	var repoPath, format string
	c := &cobra.Command{
		Use:   "scan-reachability <dir>",
		Short: "Triage dependency findings by direct-import reachability: of the flagged (malicious/typosquat/CVE) packages in a project's lockfiles, which are actually imported in first-party source (npm/PyPI/Go), and where",
		Long: `Run scan-dependencies across every lockfile under <dir>, then
determine which of the DB-flagged packages are *directly imported* in
first-party source (JavaScript/TypeScript, Python, Go) and report the
import sites.

This is DB-guided import reachability, not generic SAST: reachability
is resolved only for the packages the vulnerability DB already flagged.
Two limits are reported honestly — "imported: false" means no direct
import of that name was found, NOT that the package is unreachable or
safe. Transitive reachability (a flagged package pulled in by another
dependency) is out of scope, and a Python distribution imported under a
different module name (e.g. PyYAML -> yaml) can read as not-imported.
Reachability is additive triage; it never suppresses a finding.

Ecosystems without import analysis (Cargo, Maven, NuGet, RubyGems) are
reported as "not analyzed", never as "not imported".`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			target := args[0]
			lib, err := newLibraryForCmd(repoPath, "", target)
			if err != nil {
				return err
			}
			targetAbs, _ := filepath.Abs(target)
			info, err := os.Stat(targetAbs)
			if err != nil {
				return fmt.Errorf("scan-reachability: stat %s: %w", target, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("scan-reachability: %s is not a directory (reachability needs a project source tree)", target)
			}
			if err := lib.SetAllowedRoots([]string{targetAbs}); err != nil {
				return fmt.Errorf("scan-reachability: scope library to %s: %w", targetAbs, err)
			}
			rep, err := lib.AnalyzeReachability(targetAbs)
			if err != nil {
				return err
			}
			if format == "json" {
				return emitJSON(c.OutOrStdout(), rep)
			}
			printReachabilityText(c.OutOrStdout(), target, rep)
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, false)
	return c
}

// printReachabilityText renders the per-finding reachability verdict plus
// the import sites for any package found imported. The CycloneDX-style
// JSON document is emitted only under --format json.
func printReachabilityText(w io.Writer, target string, rep *tools.ReachabilityReport) {
	fmt.Fprintf(w, "=== scan-reachability %s ===\n", target)
	fmt.Fprintf(w, "Flagged dependencies: %d  (imported: %d · not imported: %d · not analyzed: %d)\n",
		len(rep.Findings), rep.ImportedCount, rep.NotImportedCount, rep.NotAnalyzedCount)
	for _, f := range rep.Findings {
		verdict := "not imported"
		switch {
		case !f.Analyzed:
			verdict = "not analyzed"
		case f.Imported:
			verdict = "IMPORTED"
		}
		pv := f.Package
		if f.Version != "" {
			pv += "@" + f.Version
		}
		fmt.Fprintf(w, "  [%-12s] %-8s %-7s %s (%s)\n", verdict, f.Severity, f.Ecosystem, pv, f.Category)
		for _, s := range f.Sites {
			fmt.Fprintf(w, "        %s:%d\n", s.File, s.Line)
		}
	}
}

// =============================================================================
// scan-cve-patterns
// =============================================================================

func scanCVEPatternsCmd() *cobra.Command {
	var repoPath, format string
	c := &cobra.Command{
		Use:   "scan-cve-patterns <dir>",
		Short: "Scan first-party source for the curated code patterns of known CVEs (Log4Shell, Shellshock, Spring4Shell, …), language-scoped — advisory CVE reachability at the source level",
		Long: `Walk the source tree under <dir> and, for each file, apply the
curated code_patterns of every CVE in the verified DB that declares the
file's language, reporting each match with file:line.

This is DB-guided depth, not generic SAST: only the hand-tuned CVE
regexes shipped in the library run, and only against matching languages.
It is ADVISORY — a match means a pattern associated with the CVE is
present (verify it); it is not proof of exploitability, and it is NOT
wired into the build-failing gate. Patterns that cannot compile under
Go's RE2 engine are skipped and counted.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			target := args[0]
			lib, err := newLibraryForCmd(repoPath, "", target)
			if err != nil {
				return err
			}
			targetAbs, _ := filepath.Abs(target)
			info, err := os.Stat(targetAbs)
			if err != nil {
				return fmt.Errorf("scan-cve-patterns: stat %s: %w", target, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("scan-cve-patterns: %s is not a directory (CVE-pattern scanning needs a source tree)", target)
			}
			if err := lib.SetAllowedRoots([]string{targetAbs}); err != nil {
				return fmt.Errorf("scan-cve-patterns: scope library to %s: %w", targetAbs, err)
			}
			rep, err := lib.ScanCVEPatterns(targetAbs)
			if err != nil {
				return err
			}
			switch format {
			case "json":
				return emitJSON(c.OutOrStdout(), rep)
			case "sarif":
				return emitJSON(c.OutOrStdout(), tools.ScanCVEPatternsSARIF(rep))
			default:
				printCVEPatternsText(c.OutOrStdout(), target, rep)
				return nil
			}
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, true)
	return c
}

// printCVEPatternsText renders the per-finding CVE code-pattern matches plus
// a scan summary (files scanned, active/skipped patterns). The SARIF log is
// emitted only under --format sarif.
func printCVEPatternsText(w io.Writer, target string, rep *tools.CVEReachabilityReport) {
	fmt.Fprintf(w, "=== scan-cve-patterns %s ===\n", target)
	fmt.Fprintf(w, "Files scanned: %d · patterns active: %d (skipped: %d) · findings: %d\n",
		rep.FilesScanned, rep.PatternsActive, rep.PatternsSkipped, len(rep.Findings))
	for _, f := range rep.Findings {
		fmt.Fprintf(w, "  ! [%s] %s (%s) %s:%d\n", f.Severity, f.CVE, f.Name, f.File, f.Line)
		fmt.Fprintf(w, "        match: %s\n", f.Match)
	}
}

// =============================================================================
// scan-deep
// =============================================================================

func scanDeepCmd() *cobra.Command {
	var repoPath, format string
	c := &cobra.Command{
		Use:   "scan-deep <dir>",
		Short: "Reachability-prioritized triage: merge scan-dependencies + import reachability + CVE code-patterns into one ranked list (what to fix first)",
		Long: `Run the dependency-side detection legs over <dir> — malicious /
typosquat / CVE dependency findings, DQ-V.1 import reachability, and DQ-V.2
CVE code-pattern reachability — and merge them into ONE list ranked by
reachability:

  P1 (reachable)     a flagged package you directly import, or a CVE code
                     pattern present in your source — the risk is in code
                     you wrote or import.
  P2 (present only)  a flagged package in a lockfile you do not import
                     (likely transitive — verify) or whose ecosystem has no
                     import analysis.

Within a tier, findings sort by severity. This is ADVISORY (it composes
advisory legs) and is not wired into the build-failing gate.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			target := args[0]
			lib, err := newLibraryForCmd(repoPath, "", target)
			if err != nil {
				return err
			}
			targetAbs, _ := filepath.Abs(target)
			info, err := os.Stat(targetAbs)
			if err != nil {
				return fmt.Errorf("scan-deep: stat %s: %w", target, err)
			}
			if !info.IsDir() {
				return fmt.Errorf("scan-deep: %s is not a directory (deep scan needs a project source tree)", target)
			}
			if err := lib.SetAllowedRoots([]string{targetAbs}); err != nil {
				return fmt.Errorf("scan-deep: scope library to %s: %w", targetAbs, err)
			}
			rep, err := lib.DeepScan(targetAbs)
			if err != nil {
				return err
			}
			if format == "json" {
				return emitJSON(c.OutOrStdout(), rep)
			}
			printDeepScanText(c.OutOrStdout(), target, rep)
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, false)
	return c
}

// printDeepScanText renders the reachability-prioritized triage list, each
// finding with its P-tier, severity, kind, and the one-line rationale.
func printDeepScanText(w io.Writer, target string, rep *tools.DeepScanReport) {
	fmt.Fprintf(w, "=== scan-deep %s ===\n", target)
	fmt.Fprintf(w, "Prioritized findings: %d  (P1 reachable: %d · P2 present: %d)\n",
		len(rep.Findings), rep.P1Count, rep.P2Count)
	for _, f := range rep.Findings {
		loc := ""
		if f.File != "" {
			loc = fmt.Sprintf(" — %s:%d", f.File, f.Line)
		}
		fmt.Fprintf(w, "  P%d [%s] %-11s %s\n", f.Priority, f.Severity, f.Kind, f.Title)
		fmt.Fprintf(w, "        %s%s\n", f.Why, loc)
	}
}

// =============================================================================
// gate (formerly policy-check)
// =============================================================================

func policyCheckCmd() *cobra.Command {
	var repoPath, severityFloor, format, sarifBase, report string
	c := &cobra.Command{
		Use:     "gate <file-or-dir>...",
		Aliases: []string{"policy-check"},
		Short:   "Scan files (or every config file under a directory) and exit non-zero when any finding meets the severity floor",
		Long: `gate chooses between scan-dependencies / scan-dockerfile /
scan-github-actions based on the input file shape, falling back to
scan-secrets for any other file, and returns a CI-friendly exit code:
0 when nothing meets the severity floor, 1 when at least one finding
does. severity-floor defaults to "high".

Arguments may be files or directories. A named file is always scanned.
A directory is walked — skipping .git, node_modules, vendor, build
output, etc. — and gated for both specialised findings (Dockerfiles,
lockfiles, .github/workflows/*.yml) and secrets in any other text file.
Empty, oversized, and binary files are skipped during the walk.

This is the canonical "fail the build" CLI entry point. Wrap it in a
shell call from your pre-commit or CI step.

(Formerly named "policy-check"; that name still works as an alias.)

` + reportHelpParagraph,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, true); err != nil {
				return err
			}
			// Gate over every file argument so a pre-commit hook can pass
			// the whole staged set (and a CI step a changed-file list) in
			// one invocation. Directory arguments are expanded to the
			// specialised-scanner files beneath them (Dockerfiles,
			// lockfiles, workflows), skipping noise dirs. The gate fails
			// if ANY resulting file has a finding at or above the floor.
			files, err := tools.ExpandGateFiles(args)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				fmt.Fprintf(c.OutOrStdout(),
					"gate: no scannable files found under %s; nothing to gate.\n",
					strings.Join(args, " "))
				return nil
			}
			var results []*tools.PolicyCheckResult
			floor := severityFloor
			failures, totalFindings := 0, 0
			for _, file := range files {
				lib, err := newLibraryForCmd(repoPath, "", file)
				if err != nil {
					return err
				}
				fileAbs, _ := filepath.Abs(file)
				res, err := lib.PolicyCheck(fileAbs, severityFloor)
				if err != nil {
					return err
				}
				results = append(results, res)
				floor = res.SeverityFloor
				if !res.Pass {
					failures++
					totalFindings += len(res.Findings)
				}
			}
			if report != "" {
				// HTML + PDF report covering every gated file. Written
				// here, before the exit-code decision below, so a FAILING
				// gate still produces its report. --report-dir takes
				// precedence over --format (which targets stdout).
				rep := newReport("gate", args)
				for _, res := range results {
					rep.Sections = append(rep.Sections, gateSection(res))
				}
				if err := writeReport(c, report, rep); err != nil {
					return err
				}
				if failures > 0 {
					c.SilenceUsage = true
					return &policyFailureError{count: totalFindings, floor: floor}
				}
				return nil
			}
			switch format {
			case "json":
				// Single file → one object (back-compat); many → an array.
				if len(results) == 1 {
					_ = emitJSON(c.OutOrStdout(), results[0])
				} else {
					_ = emitJSON(c.OutOrStdout(), results)
				}
			case "sarif":
				// One SARIF run covering every scanned file. Emitted here,
				// before the exit-code decision below, so a FAILING gate
				// still writes a valid SARIF document for `upload-sarif`.
				// URIs are made relative to --sarif-base (default cwd) so
				// GitHub Code Scanning anchors alerts to repo files.
				base, err := filepath.Abs(sarifBase)
				if err != nil {
					base = ""
				}
				_ = emitJSON(c.OutOrStdout(), tools.PolicyCheckSARIF(results, base))
			default:
				for i, res := range results {
					verdict := "PASS"
					if !res.Pass {
						verdict = "FAIL"
					}
					fmt.Fprintf(c.OutOrStdout(), "=== gate %s ===\n", files[i])
					fmt.Fprintf(c.OutOrStdout(), "Verdict:        %s\n", verdict)
					fmt.Fprintf(c.OutOrStdout(), "Severity floor: %s\n", res.SeverityFloor)
					fmt.Fprintf(c.OutOrStdout(), "Scanner used:   %s\n", res.Scan)
					fmt.Fprintf(c.OutOrStdout(), "Findings: %d\n", len(res.Findings))
					for sev, n := range res.Counts {
						fmt.Fprintf(c.OutOrStdout(), "  %s: %d\n", sev, n)
					}
				}
				if len(results) > 1 {
					fmt.Fprintf(c.OutOrStdout(), "=== %d file(s), %d failing ===\n", len(results), failures)
				}
			}
			// Surface the result via exit code so a CI / pre-commit step
			// can gate on a single command. We return a sentinel error
			// rather than os.Exit so the Cobra layer can still print any
			// final state and tests can observe the failure.
			if failures > 0 {
				// Hide usage on a policy failure — this is not a
				// flag-error, just findings.
				c.SilenceUsage = true
				return &policyFailureError{count: totalFindings, floor: floor}
			}
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	c.Flags().StringVar(&severityFloor, "severity-floor", "high",
		"the lowest severity that causes a non-zero exit: critical | high | medium | low")
	c.Flags().StringVar(&sarifBase, "sarif-base", ".",
		"directory SARIF artifact URIs are made relative to (files outside it fall back to absolute file:// URIs); only used with --format sarif")
	addFormatFlag(c, &format, true)
	addReportFlag(c, &report)
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
	return fmt.Sprintf("gate: %d finding(s) at or above %s", e.count, e.floor)
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
