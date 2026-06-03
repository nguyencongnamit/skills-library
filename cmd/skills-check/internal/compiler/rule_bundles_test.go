package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWriteRuleBundlesEmitsPerSkillFiles(t *testing.T) {
	skills := loadAllSkills(t)
	if len(skills) == 0 {
		t.Skip("no skills available")
	}
	outDir := t.TempDir()
	if err := WriteRuleBundles(skills, outDir); err != nil {
		t.Fatalf("WriteRuleBundles: %v", err)
	}
	cursorDir := filepath.Join(outDir, "cursor-rules", ".cursor", "rules")
	copilotDir := filepath.Join(outDir, "copilot-rules", ".github", "instructions")
	for _, s := range skills {
		mdc := filepath.Join(cursorDir, s.Frontmatter.ID+".mdc")
		ins := filepath.Join(copilotDir, s.Frontmatter.ID+".instructions.md")
		if info, err := os.Stat(mdc); err != nil || info.Size() == 0 {
			t.Errorf("missing/empty %s: %v", mdc, err)
		}
		if info, err := os.Stat(ins); err != nil || info.Size() == 0 {
			t.Errorf("missing/empty %s: %v", ins, err)
		}
	}
}

// TestRuleBundleScoping checks the token-optimization contract: a
// language-specific skill auto-attaches by glob, while a broad (languages:
// ["*"]) skill drops globs (Cursor Agent-Requested) and applies to "**"
// (Copilot).
func TestRuleBundleScoping(t *testing.T) {
	skills := loadAllSkills(t)
	byID := map[string]bool{}
	for _, s := range skills {
		byID[s.Frontmatter.ID] = true
	}
	for _, id := range []string{"container-security", "secret-detection"} {
		if !byID[id] {
			t.Skipf("required skill %q not present", id)
		}
	}
	outDir := t.TempDir()
	if err := WriteRuleBundles(skills, outDir); err != nil {
		t.Fatalf("WriteRuleBundles: %v", err)
	}

	// container-security: language-specific -> has globs in .mdc.
	csMdc := readFile(t, filepath.Join(outDir, "cursor-rules", ".cursor", "rules", "container-security.mdc"))
	if !strings.Contains(csMdc, "\nglobs: ") {
		t.Errorf("container-security.mdc should carry a globs line; got:\n%s", firstLines(csMdc, 5))
	}
	if !strings.Contains(csMdc, "Dockerfile") {
		t.Errorf("container-security.mdc globs should include a Dockerfile pattern")
	}

	// secret-detection: broad -> NO globs line; copilot applyTo "**".
	sdMdc := readFile(t, filepath.Join(outDir, "cursor-rules", ".cursor", "rules", "secret-detection.mdc"))
	if strings.Contains(sdMdc, "\nglobs: ") {
		t.Errorf("secret-detection.mdc (broad) should NOT carry globs; got:\n%s", firstLines(sdMdc, 5))
	}
	sdIns := readFile(t, filepath.Join(outDir, "copilot-rules", ".github", "instructions", "secret-detection.instructions.md"))
	var fm struct {
		ApplyTo string `yaml:"applyTo"`
	}
	if err := yaml.Unmarshal([]byte(frontmatter(sdIns)), &fm); err != nil {
		t.Fatalf("secret-detection.instructions.md frontmatter not valid YAML: %v", err)
	}
	if fm.ApplyTo != "**" {
		t.Errorf("secret-detection applyTo = %q, want \"**\"", fm.ApplyTo)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read %s: %v", p, err)
	}
	return string(b)
}

func frontmatter(s string) string {
	parts := strings.SplitN(s, "---", 3)
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
