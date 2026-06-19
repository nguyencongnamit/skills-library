package cmd

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/namncqualgo/skills-library/internal/tools"
)

func TestCWECmdText(t *testing.T) {
	root := repoRoot(t)
	stdout, stderr, err := executeRoot(t, "cwe", "CWE-798", "--path", root)
	if err != nil {
		t.Fatalf("cwe command failed: %v\nstderr: %s", err, stderr)
	}
	// CWE-798 (hardcoded credentials) must surface its canonical id and at
	// least one of the controls that cite it.
	for _, want := range []string{"CWE-798", "secret-detection", "scan_secrets", "CC6.7"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("cwe text output missing %q; got:\n%s", want, stdout)
		}
	}
}

func TestCWECmdJSONBareNumber(t *testing.T) {
	root := repoRoot(t)
	stdout, _, err := executeRoot(t, "cwe", "1104", "--path", root, "--format", "json")
	if err != nil {
		t.Fatalf("cwe --format json failed: %v", err)
	}
	var res tools.CWESpineResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, stdout)
	}
	if res.CWE != "CWE-1104" {
		t.Errorf("bare number 1104 should normalize to CWE-1104, got %q", res.CWE)
	}
	if res.ControlCount == 0 || len(res.Frameworks) == 0 {
		t.Errorf("CWE-1104 should map to controls, got %+v", res)
	}
}

func TestCWECmdInvalidErrors(t *testing.T) {
	root := repoRoot(t)
	if _, _, err := executeRoot(t, "cwe", "not-a-cwe", "--path", root); err == nil {
		t.Error("cwe command must reject a malformed CWE")
	}
}
