package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/namncqualgo/skills-library/internal/skill"
)

type corpusFixture struct {
	ID              string `json:"id"`
	Text            string `json:"text"`
	Expected        string `json:"expected"` // "detect" or "ignore"
	ExpectedPattern string `json:"expected_pattern,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

type corpusFile struct {
	SchemaVersion string          `json:"schema_version"`
	Description   string          `json:"description"`
	Fixtures      []corpusFixture `json:"fixtures"`
}

// rulePatternEntry mirrors the subset of fields the test runner needs
// from one `checks:` entry of checklists/secret_detection.yaml. It is
// intentionally narrower than internal/tools.Pattern: the runner only
// applies regex + hotword + denylist gating, not score / entropy
// thresholds (those belong to CheckSecretPattern's full pipeline).
type rulePatternEntry struct {
	ID                 string   `yaml:"id"`
	Type               string   `yaml:"type"`
	Title              string   `yaml:"title"`
	Pattern            string   `yaml:"pattern"`
	Hotwords           []string `yaml:"hotwords"`
	HotwordWindow      int      `yaml:"hotword_window"`
	RequireHotword     bool     `yaml:"require_hotword"`
	DenylistSubstrings []string `yaml:"denylist_substrings"`
}

type rulePatternFile struct {
	Checks []rulePatternEntry `yaml:"checks"`
}

func testCmd() *cobra.Command {
	var libraryPath string
	var verbose bool

	c := &cobra.Command{
		Use:   "test <skill-id>",
		Short: "Run the per-skill test corpus and report pass/fail",
		Long: `Load skills/<id>/tests/corpus.json and validate each fixture
against the skill's bundled rule files.

The runner supports two corpus shapes:

  * Regex-driven (e.g., secret-detection): the corpus declares "detect" or
    "ignore" per fixture, and the runner matches the text against any
    type: secret_pattern entry declared in
    skills/<id>/checklists/<framework>.yaml (with hotword window enforcement).
  * Schema-driven (other skills): the corpus is treated as a smoke test; the
    runner only verifies that fixtures parse and that "expected" is one of the
    accepted values.

Exits non-zero on any failure.
`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			id := strings.TrimSpace(args[0])

			lib, err := filepath.Abs(libraryPath)
			if err != nil {
				return err
			}
			skillDir := filepath.Join(lib, "skills", id)
			if _, err := os.Stat(skillDir); err != nil {
				return fmt.Errorf("skill %q not found at %s", id, skillDir)
			}
			s, err := skill.Parse(filepath.Join(skillDir, "SKILL.md"))
			if err != nil {
				return fmt.Errorf("load skill: %w", err)
			}

			corpusPath := filepath.Join(skillDir, "tests", "corpus.json")
			if _, err := os.Stat(corpusPath); err != nil {
				fmt.Fprintf(c.OutOrStdout(), "no tests/corpus.json for %s; nothing to test\n", id)
				return nil
			}

			data, err := os.ReadFile(corpusPath)
			if err != nil {
				return err
			}
			var corpus corpusFile
			if err := json.Unmarshal(data, &corpus); err != nil {
				return fmt.Errorf("parse corpus: %w", err)
			}

			patterns := loadRulePatterns(skillDir)
			passed, failed := 0, 0
			out := c.OutOrStdout()

			for _, fx := range corpus.Fixtures {
				if fx.Expected != "detect" && fx.Expected != "ignore" {
					failed++
					fmt.Fprintf(out, "FAIL [%s]: expected must be 'detect' or 'ignore', got %q\n", fx.ID, fx.Expected)
					continue
				}
				if len(patterns) == 0 {
					// Schema-only smoke pass
					passed++
					if verbose {
						fmt.Fprintf(out, "ok   [%s] (schema-only)\n", fx.ID)
					}
					continue
				}
				match, matchedName := matchAny(fx.Text, patterns)
				wantDetect := fx.Expected == "detect"
				if match != wantDetect {
					failed++
					fmt.Fprintf(out, "FAIL [%s]: expected=%s actual=%s pattern=%s\n", fx.ID, fx.Expected, boolStr(match), matchedName)
					continue
				}
				if match && fx.ExpectedPattern != "" && fx.ExpectedPattern != matchedName {
					failed++
					fmt.Fprintf(out, "FAIL [%s]: matched %q but expected_pattern was %q\n", fx.ID, matchedName, fx.ExpectedPattern)
					continue
				}
				passed++
				if verbose {
					fmt.Fprintf(out, "ok   [%s] -> %s\n", fx.ID, matchedName)
				}
			}

			fmt.Fprintf(out, "%s: %d passed, %d failed (skill v%s)\n", id, passed, failed, s.Frontmatter.Version)
			if failed > 0 {
				return fmt.Errorf("%d fixture(s) failed", failed)
			}
			return nil
		},
	}

	c.Flags().StringVar(&libraryPath, "library", ".", "Path to the skills library root")
	c.Flags().BoolVar(&verbose, "verbose", false, "Print one line per fixture")
	return c
}

func boolStr(b bool) string {
	if b {
		return "detect"
	}
	return "ignore"
}

// loadRulePatterns reads the first checklists/*.yaml in skills/<id>/
// and returns every `type: secret_pattern` entry compiled into a
// runnable shape. Skills without a checklists/ directory or without
// any secret_pattern items return an empty slice and the test runner
// falls back to schema-only smoke validation.
func loadRulePatterns(skillDir string) []compiledPattern {
	checklistsDir := filepath.Join(skillDir, "checklists")
	entries, err := os.ReadDir(checklistsDir)
	if err != nil {
		return nil
	}
	out := []compiledPattern{}
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		name := ent.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(checklistsDir, name))
		if err != nil {
			continue
		}
		var f rulePatternFile
		if err := yaml.Unmarshal(data, &f); err != nil {
			continue
		}
		for _, c := range f.Checks {
			if c.Type != "secret_pattern" {
				continue
			}
			re, err := regexp.Compile(c.Pattern)
			if err != nil {
				continue
			}
			out = append(out, compiledPattern{
				Name:               c.Title,
				Regex:              re,
				Hotwords:           c.Hotwords,
				HotwordWindow:      c.HotwordWindow,
				RequireHotword:     c.RequireHotword,
				DenylistSubstrings: c.DenylistSubstrings,
			})
		}
	}
	return out
}

type compiledPattern struct {
	Name               string
	Regex              *regexp.Regexp
	Hotwords           []string
	HotwordWindow      int
	RequireHotword     bool
	DenylistSubstrings []string
}

// matchAny returns whether the text matches any compiled pattern. When
// multiple patterns match, the most specific one (i.e. the last non-Generic
// pattern that matched) wins.
func matchAny(text string, patterns []compiledPattern) (bool, string) {
	bestName := ""
	for _, p := range patterns {
		loc := p.Regex.FindStringIndex(text)
		if loc == nil {
			continue
		}
		matchText := text[loc[0]:loc[1]]
		if denylisted(matchText, p.DenylistSubstrings) {
			continue
		}
		if p.RequireHotword || len(p.Hotwords) > 0 {
			if !hotwordNear(text, loc, p.Hotwords, p.HotwordWindow) {
				if p.RequireHotword {
					continue
				}
			}
		}
		isGeneric := strings.HasPrefix(p.Name, "Generic ")
		// Selection rule (per the doc comment above):
		//   - The first match seeds the best (Generic or not).
		//   - Any later non-Generic match replaces the current best,
		//     so the LAST non-Generic in iteration order wins.
		//   - Generic matches after the first never replace, keeping
		//     the earliest seed stable when no non-Generic matches.
		if bestName == "" || !isGeneric {
			bestName = p.Name
		}
	}
	if bestName == "" {
		return false, ""
	}
	return true, bestName
}

func denylisted(matchText string, denylist []string) bool {
	if len(denylist) == 0 {
		return false
	}
	lower := strings.ToLower(matchText)
	for _, sub := range denylist {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// hotwordNear returns true if any hotword appears within `window` bytes of the
// regex match indicated by matchIdx, where matchIdx is a [start, end) byte
// range over the original-case `text`. The window is lowered together with the
// slice so the byte indices and the lowered string come from the same byte
// space — strings.ToLower is not length-preserving (e.g. U+2126 OHM SIGN →
// U+03C9, 3 → 2 bytes; Turkish İ → i, 2 → 1 byte), so pre-lowering the full
// text would shift the window relative to the match and produce false
// negatives (or panics) on non-ASCII input.
func hotwordNear(text string, matchIdx []int, hotwords []string, window int) bool {
	if window <= 0 {
		window = 80
	}
	start := matchIdx[0] - window
	if start < 0 {
		start = 0
	}
	if start > len(text) {
		start = len(text)
	}
	end := matchIdx[1] + window
	if end > len(text) {
		end = len(text)
	}
	if end < start {
		end = start
	}
	region := strings.ToLower(text[start:end])
	for _, h := range hotwords {
		if strings.Contains(region, strings.ToLower(h)) {
			return true
		}
	}
	return false
}
