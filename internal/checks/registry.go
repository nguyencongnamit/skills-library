// Package checks is the canonical registry of automated detection checks
// the library can run.
//
// A "check" is a runnable detection with a stable ID. The registry is the
// single source of truth that ties three things together:
//
//   - the MCP tools / CLI scanners that actually execute the detection
//     (internal/tools),
//   - the compliance mappings that cite a check to VERIFY a control
//     (compliance/*.yaml, schema 2.0 — see internal/compliance), and
//   - `skills-check validate`, which fails CI when a mapping references a
//     check ID that does not exist here.
//
// Keeping the IDs here (rather than as free-form strings in YAML) means a
// control can only be backed by a detection the engine can really run, so
// a compliance "evidence" report can never claim verification it cannot
// perform. When a new scanner ships, register it here in the same change.
package checks

import "sort"

// Kind classifies how a check is executed.
type Kind string

const (
	// KindScanner walks a path / parses files and emits findings (SARIF).
	KindScanner Kind = "scanner"
	// KindLookup answers a question about a single artifact (a package, a
	// string) against the vulnerability DB / OSV.
	KindLookup Kind = "lookup"
)

// Check is one registered detection.
type Check struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Kind        Kind   `json:"kind"`
	Description string `json:"description"`
	// CWE lists weakness identifiers this check commonly surfaces. Used by
	// the CWE spine that joins checks to compliance controls; informational.
	CWE []string `json:"cwe,omitempty"`
}

// registry is keyed by stable check ID. The IDs intentionally match the
// MCP tool names (cmd/skills-mcp) and CLI subcommands so a control author,
// an LLM, and an operator all refer to a check by one name.
var registry = map[string]Check{
	"scan_dependencies": {
		ID:          "scan_dependencies",
		Title:       "Dependency scan",
		Kind:        KindScanner,
		Description: "Parse lockfiles and check every resolved (name, version) against the malicious / typosquat / CVE / OSV databases.",
		CWE:         []string{"CWE-1104", "CWE-937"},
	},
	"scan_secrets": {
		ID:          "scan_secrets",
		Title:       "Secret scan",
		Kind:        KindScanner,
		Description: "DLP-style scan of files for credentials, API keys, tokens, and PEM material.",
		CWE:         []string{"CWE-798", "CWE-312"},
	},
	"scan_dockerfile": {
		ID:          "scan_dockerfile",
		Title:       "Dockerfile hardening scan",
		Kind:        KindScanner,
		Description: "Hardening pass over a Dockerfile (USER root, unpinned base, ADD remote, curl|sh, secrets in env, etc.).",
		CWE:         []string{"CWE-250", "CWE-15"},
	},
	"scan_github_actions": {
		ID:          "scan_github_actions",
		Title:       "GitHub Actions workflow scan",
		Kind:        KindScanner,
		Description: "Lint a GitHub Actions workflow for pwn-request, script-injection, unpinned actions, missing permissions, and credential exposure.",
		CWE:         []string{"CWE-94", "CWE-829"},
	},
	"check_dependency": {
		ID:          "check_dependency",
		Title:       "Single-package check",
		Kind:        KindLookup,
		Description: "Check a package@version for known malicious entries, typosquats, CVE patterns, and OSV advisories.",
		CWE:         []string{"CWE-1104"},
	},
	"check_typosquat": {
		ID:          "check_typosquat",
		Title:       "Typosquat check",
		Kind:        KindLookup,
		Description: "Flag candidate typosquats against the curated DB plus a Levenshtein-2 sweep over popular packages.",
		CWE:         []string{"CWE-1357"},
	},
	"lookup_vulnerability": {
		ID:          "lookup_vulnerability",
		Title:       "Vulnerability lookup",
		Kind:        KindLookup,
		Description: "Search the supply-chain malicious-packages corpus and OSV advisories for a package.",
		CWE:         []string{"CWE-937"},
	},
	"check_secret_pattern": {
		ID:          "check_secret_pattern",
		Title:       "Secret-pattern check",
		Kind:        KindLookup,
		Description: "Test a string against the DLP credential/secret pattern set.",
		CWE:         []string{"CWE-798"},
	},
}

// Lookup returns the registered check for id and whether it exists.
func Lookup(id string) (Check, bool) {
	c, ok := registry[id]
	return c, ok
}

// IsKnown reports whether id is a registered check.
func IsKnown(id string) bool {
	_, ok := registry[id]
	return ok
}

// All returns every registered check, sorted by ID for stable output.
func All() []Check {
	out := make([]Check, 0, len(registry))
	for _, c := range registry {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IDs returns every registered check ID, sorted.
func IDs() []string {
	out := make([]string, 0, len(registry))
	for id := range registry {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ByCWE returns the IDs of every registered check whose CWE list includes
// cwe (e.g. "CWE-798"), sorted. It is one leg of the CWE cross-framework
// spine: given a weakness, which runnable detections surface it. Returns an
// empty slice when no check is tagged with the CWE.
func ByCWE(cwe string) []string {
	var out []string
	for id, c := range registry {
		for _, w := range c.CWE {
			if w == cwe {
				out = append(out, id)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
