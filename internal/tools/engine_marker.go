package tools

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Engine marker syntax — extends the PR #4 pattern-marker convention
// (see derive_checklists.go) with a parallel `engine:` payload that
// declares a scanner-engine entry in SKILL.md:
//
//	<!-- engine: {
//	  name: hadolint,
//	  type: external,
//	  scanner: dockerfile,
//	  binary: hadolint,
//	  detect: [hadolint, --version],
//	  execute: [hadolint, --format, sarif, "{file_path}"],
//	  output_format: sarif,
//	  install_hint: "brew install hadolint",
//	  upstream: "https://github.com/hadolint/hadolint"
//	} -->
//
// SKILL.md author drops these markers wherever they want (typically
// under a `## Scanner engines` H2 section). The MCP server scans every
// SKILL.md at startup and groups markers by `scanner` field, so
// `scan_dockerfile_engines` can answer "what's available right now?"
// without the MCP server needing to know upstream what engines exist.
//
// Adding a new engine = edit the relevant SKILL.md. Zero Go code
// change required when the engine emits SARIF (the generic parser
// handles that). Non-SARIF outputs still need a Go parser, registered
// against the `output_format` value.
//
// Field reference:
//
//	name           REQUIRED. kebab-case engine identifier (e.g.
//	               "hadolint"). Unique within a scanner type.
//	type           REQUIRED. "builtin" for the in-process scanner
//	               that ships with secure-code, "external" for a
//	               CLI tool that must be on PATH.
//	scanner        REQUIRED. Scanner type this engine handles —
//	               "dockerfile", "github_actions", "secrets",
//	               "dependencies", etc.
//	description    OPTIONAL. One-line summary, surfaced in the
//	               discovery menu.
//	binary         OPTIONAL (required when type=external). The
//	               binary name to look up on PATH (`exec.LookPath`).
//	detect         OPTIONAL. argv used to verify the engine is
//	               functional; non-zero exit means not available.
//	               Defaults to [binary, --version] when omitted for
//	               external engines.
//	execute        OPTIONAL. argv template used to run the scan.
//	               Tokens "{file_path}" are substituted by the
//	               dispatcher. Required for type=external; ignored
//	               for builtin (the in-process scanner has its own
//	               handler).
//	output_format  OPTIONAL. How the engine's stdout should be
//	               parsed. Known values: "sarif" (generic SARIF
//	               2.1.0 parser), "dockerfile_finding" (the existing
//	               internal scanner output shape — used by builtin
//	               engines). Non-SARIF formats need a Go parser
//	               registered against the value.
//	install_hint   OPTIONAL. Shell command the user can run to
//	               install the engine. Surfaced in the discovery
//	               menu when binary is missing.
//	upstream       OPTIONAL. URL of the upstream project, surfaced
//	               for reviewer audit.
var htmlEngineMarker = regexp.MustCompile(`(?s)<!--\s*engine\s*:\s*(\{.*?\})\s*-->`)

// EngineMarker is one engine entry extracted from a SKILL.md HTML
// comment. The struct mirrors the YAML payload tag-for-tag so a
// `yaml.Unmarshal` of the comment body produces a fully populated
// EngineMarker directly.
type EngineMarker struct {
	Name         string   `yaml:"name"`
	Type         string   `yaml:"type"`
	Scanner      string   `yaml:"scanner"`
	Description  string   `yaml:"description,omitempty"`
	Binary       string   `yaml:"binary,omitempty"`
	Detect       []string `yaml:"detect,omitempty"`
	Execute      []string `yaml:"execute,omitempty"`
	OutputFormat string   `yaml:"output_format,omitempty"`
	InstallHint  string   `yaml:"install_hint,omitempty"`
	Upstream     string   `yaml:"upstream,omitempty"`

	// SkillID is filled in by the registry loader so a downstream
	// renderer can attribute "this engine came from skill X". Not part
	// of the on-disk payload — populated post-parse.
	SkillID string `yaml:"-"`
}

// AllowedEngineTypes enumerates the legal values for EngineMarker.Type.
// Anything else is rejected at extraction time so a typo in SKILL.md
// surfaces as a build error rather than silently dropping the engine.
var AllowedEngineTypes = map[string]bool{
	"builtin":  true,
	"external": true,
}

// AllowedScannerTypes enumerates the scanner buckets engines may
// register against. Keep in sync with the scan_* MCP tools.
var AllowedScannerTypes = map[string]bool{
	"dockerfile":     true,
	"github_actions": true,
	"secrets":        true,
	"dependencies":   true,
}

// AllowedOutputFormats enumerates the parsers the dispatcher knows how
// to wire up. The empty string is allowed for builtin engines whose
// output stays in the in-process DockerfileFinding shape (or the
// equivalent shape per scanner).
var AllowedOutputFormats = map[string]bool{
	"":                   true, // builtin or "no external parser needed"
	"sarif":              true,
	"dockerfile_finding": true, // alias for builtin Dockerfile output
}

// extractEngineMarkers walks the raw SKILL.md bytes and returns every
// well-formed `<!-- engine: { ... } -->` payload it can decode. Markers
// that fail to parse, fail validation, or collide with an earlier
// marker on the same (scanner, name) tuple within the same file are
// returned as errors (collected with errors.Join semantics by the
// caller; here we fail-fast for the first error to keep the SKILL.md
// author's iteration loop tight).
//
// skillID is forwarded into each EngineMarker.SkillID so the registry
// can attribute the entry back to its source file in `engines_available`
// responses; pass the kebab-case id from frontmatter (e.g.
// "container-security").
func extractEngineMarkers(skillID string, body []byte) ([]EngineMarker, error) {
	matches := htmlEngineMarker.FindAllSubmatch(body, -1)
	out := make([]EngineMarker, 0, len(matches))
	seen := map[string]bool{}
	for _, m := range matches {
		payload := m[1]
		var em EngineMarker
		if err := yaml.Unmarshal(payload, &em); err != nil {
			return nil, fmt.Errorf("skill %s: invalid engine marker %q: %w", skillID, truncateMarker(string(payload)), err)
		}
		em.SkillID = skillID
		if err := validateEngineMarker(&em); err != nil {
			return nil, fmt.Errorf("skill %s: engine %q: %w", skillID, em.Name, err)
		}
		key := em.Scanner + "/" + em.Name
		if seen[key] {
			return nil, fmt.Errorf("skill %s: duplicate engine (%s) within the same skill", skillID, key)
		}
		seen[key] = true
		out = append(out, em)
	}
	return out, nil
}

// validateEngineMarker enforces the required-field + enum constraints
// at parse time so the registry never has to second-guess a marker at
// runtime. Returning an error here surfaces as a NewLibrary() failure,
// which makes the SKILL.md author's mistake immediately obvious rather
// than a silent runtime hiccup the user can't trace back.
func validateEngineMarker(em *EngineMarker) error {
	if strings.TrimSpace(em.Name) == "" {
		return fmt.Errorf("missing required field 'name'")
	}
	if strings.TrimSpace(em.Type) == "" {
		return fmt.Errorf("missing required field 'type'")
	}
	if !AllowedEngineTypes[em.Type] {
		return fmt.Errorf("invalid type %q (allowed: builtin, external)", em.Type)
	}
	if strings.TrimSpace(em.Scanner) == "" {
		return fmt.Errorf("missing required field 'scanner'")
	}
	if !AllowedScannerTypes[em.Scanner] {
		return fmt.Errorf("invalid scanner %q (allowed: dockerfile, github_actions, secrets, dependencies)", em.Scanner)
	}
	if em.Type == "external" && strings.TrimSpace(em.Binary) == "" {
		return fmt.Errorf("external engine must declare 'binary' (the command name to look up on PATH)")
	}
	if !AllowedOutputFormats[em.OutputFormat] {
		return fmt.Errorf("invalid output_format %q (allowed: sarif, dockerfile_finding, or empty)", em.OutputFormat)
	}
	return nil
}

// truncateMarker returns at most 80 chars of s, suitable for an error
// message that needs to identify a malformed marker without flooding
// the terminal. Mirrors PR #4's truncateForError helper.
func truncateMarker(s string) string {
	s = strings.TrimSpace(s)
	if len(s) <= 80 {
		return s
	}
	return s[:77] + "..."
}
