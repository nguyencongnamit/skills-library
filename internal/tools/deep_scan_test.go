package tools

import (
	"path/filepath"
	"testing"
)

func deepOf(rep *DeepScanReport, pkgOrCVE string) *DeepFinding {
	for i := range rep.Findings {
		if rep.Findings[i].Package == pkgOrCVE || rep.Findings[i].CVE == pkgOrCVE {
			return &rep.Findings[i]
		}
	}
	return nil
}

// TestDeepScanPrioritizesByReachability builds a project where:
//   - event-stream (malicious) is directly imported  -> P1
//   - flatmap-stream (malicious) is only in the lockfile -> P2
//   - a Log4Shell code pattern is present in source  -> P1
//
// and asserts the reachability-based tiering + ordering.
func TestDeepScanPrioritizesByReachability(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	mkProjFile(t, filepath.Join(dir, "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"node_modules/event-stream":{"version":"3.3.6"},"node_modules/flatmap-stream":{"version":"0.1.1"}}}`)
	mkProjFile(t, filepath.Join(dir, "src", "app.js"), "import es from 'event-stream';\n")
	mkProjFile(t, filepath.Join(dir, "src", "A.java"),
		"class A { void f(String u){ logger.info(\"${jndi:ldap://x/\"+u); } }\n")

	rep, err := lib.DeepScan(dir)
	if err != nil {
		t.Fatalf("DeepScan: %v", err)
	}

	es := deepOf(rep, "event-stream")
	if es == nil || es.Priority != 1 || !es.Imported {
		t.Errorf("imported malicious dep should be P1 reachable, got %+v", es)
	}
	fm := deepOf(rep, "flatmap-stream")
	if fm == nil || fm.Priority != 2 {
		t.Errorf("present-but-unimported dep should be P2, got %+v", fm)
	}
	log4 := deepOf(rep, "CVE-2021-44228")
	if log4 == nil || log4.Priority != 1 || log4.Kind != "cve-pattern" {
		t.Errorf("a present CVE code pattern should be P1, got %+v", log4)
	}
	if rep.P1Count < 2 || rep.P2Count < 1 {
		t.Errorf("counts off: P1=%d P2=%d", rep.P1Count, rep.P2Count)
	}
	// All P1 findings must sort ahead of every P2 finding.
	lastP1 := -1
	for i, f := range rep.Findings {
		if f.Priority == 1 {
			lastP1 = i
		}
	}
	for i, f := range rep.Findings {
		if f.Priority == 2 && i < lastP1 {
			t.Errorf("a P2 finding at %d precedes a P1 finding at %d", i, lastP1)
		}
	}
}

func TestDeepScanCleanProject(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	mkProjFile(t, filepath.Join(dir, "go.sum"),
		"github.com/stretchr/testify v1.8.4 h1:abc=\n")
	mkProjFile(t, filepath.Join(dir, "main.go"), "package main\n\nfunc main() {}\n")
	rep, err := lib.DeepScan(dir)
	if err != nil {
		t.Fatalf("DeepScan: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("clean project should yield no triage findings, got %d: %+v", len(rep.Findings), rep.Findings)
	}
	if rep.Findings == nil {
		t.Error("Findings should be non-nil ([]) for stable JSON")
	}
}
