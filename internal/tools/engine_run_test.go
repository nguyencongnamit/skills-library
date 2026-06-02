package tools

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const sampleHadolintSARIF = `{
  "version": "2.1.0",
  "runs": [
    {
      "results": [
        {
          "ruleId": "DL3008",
          "level": "warning",
          "message": {"text": "Pin versions in apt-get install."},
          "locations": [{"physicalLocation": {"region": {"startLine": 4}}}]
        },
        {
          "ruleId": "DL3002",
          "level": "error",
          "message": {"text": "Last USER should not be root."},
          "locations": [{"physicalLocation": {"region": {"startLine": 7}}}]
        }
      ]
    }
  ]
}`

func TestParseSARIF(t *testing.T) {
	findings, err := parseSARIF([]byte(sampleHadolintSARIF), "hadolint")
	if err != nil {
		t.Fatalf("parseSARIF: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(findings))
	}
	if findings[0].RuleID != "DL3008" || findings[0].Severity != "medium" || findings[0].Line != 4 {
		t.Errorf("finding[0] = %+v; want DL3008/medium/line4", findings[0])
	}
	if findings[1].RuleID != "DL3002" || findings[1].Severity != "high" || findings[1].Line != 7 {
		t.Errorf("finding[1] = %+v; want DL3002/high/line7", findings[1])
	}
	if findings[0].Engine != "hadolint" {
		t.Errorf("engine tag = %q, want hadolint", findings[0].Engine)
	}
}

func TestParseSARIFEmptyRuns(t *testing.T) {
	findings, err := parseSARIF([]byte(`{"version":"2.1.0","runs":[]}`), "x")
	if err != nil {
		t.Fatalf("parseSARIF: %v", err)
	}
	if findings == nil || len(findings) != 0 {
		t.Errorf("want empty non-nil slice, got %v", findings)
	}
}

// writeStubEngine writes an executable shell script that prints the
// given SARIF to stdout, so the runner can be exercised without a real
// hadolint install. Skips on Windows (no /bin/sh).
func writeStubEngine(t *testing.T, dir, sarif string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("stub engine needs a POSIX shell")
	}
	p := filepath.Join(dir, "stub-engine")
	body := "#!/bin/sh\ncat <<'SARIF'\n" + sarif + "\nSARIF\n"
	if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunEngineMarkerExecutesAndParses(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	stub := writeStubEngine(t, dir, sampleHadolintSARIF)
	target := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(target, []byte("FROM node\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := &EngineMarker{
		Name:         "stub",
		Type:         "external",
		Scanner:      "dockerfile",
		Binary:       stub, // absolute path resolves via exec.LookPath
		Execute:      []string{stub, "{file_path}"},
		OutputFormat: "sarif",
	}
	res, err := lib.runEngineMarker(marker, target)
	if err != nil {
		t.Fatalf("runEngineMarker: %v", err)
	}
	if res.Engine != "stub" || res.Type != "external" || res.Scanner != "dockerfile" {
		t.Errorf("result meta = %+v", res)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(res.Findings))
	}
	if res.Findings[1].RuleID != "DL3002" || res.Findings[1].Severity != "high" {
		t.Errorf("finding[1] = %+v", res.Findings[1])
	}
}

func TestRunEngineMarkerRejectsRelativePath(t *testing.T) {
	lib := newLibrary(t)
	marker := &EngineMarker{Name: "stub", Type: "external", Scanner: "dockerfile", Binary: "true", Execute: []string{"true"}, OutputFormat: "sarif"}
	if _, err := lib.runEngineMarker(marker, "relative/Dockerfile"); err == nil {
		t.Error("expected error for relative path")
	}
}

func TestRunEngineMarkerBinaryMissing(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(target, []byte("FROM node\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := &EngineMarker{
		Name: "ghost", Type: "external", Scanner: "dockerfile",
		Binary: "definitely-not-a-real-binary-xyz", Execute: []string{"definitely-not-a-real-binary-xyz", "{file_path}"},
		OutputFormat: "sarif", InstallHint: "brew install ghost",
	}
	_, err := lib.runEngineMarker(marker, target)
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
}

func TestRunEngineRejectsBuiltin(t *testing.T) {
	lib := newLibrary(t)
	// container-security declares the builtin "internal" dockerfile engine;
	// RunEngine must refuse to "execute" it.
	if _, err := lib.RunEngine("dockerfile", "internal", "/tmp/Dockerfile"); err == nil {
		t.Error("expected error routing a builtin engine through RunEngine")
	}
}

func TestRunEngineUnknownEngine(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.RunEngine("dockerfile", "no-such-engine", "/tmp/Dockerfile"); err == nil {
		t.Error("expected error for undeclared engine")
	}
}
