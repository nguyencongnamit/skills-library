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
//   - event-stream (malicious) is directly imported            -> P1 reachable
//   - flatmap-stream (malicious) is pulled in BY event-stream
//     (the real 2018 supply-chain edge) so it is reachable-via -> P2 transitive
//   - a Log4Shell code pattern is present in source            -> P1
//
// and asserts the reachability tiering, the DQ-H.3 transitive `via` path, and
// that every P1 sorts ahead of lower-priority findings.
func TestDeepScanPrioritizesByReachability(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	// event-stream@3.3.6 declares flatmap-stream@0.1.1 as a dependency — the
	// real compromise edge — so flatmap-stream is reachable transitively even
	// though first-party source imports only event-stream.
	mkProjFile(t, filepath.Join(dir, "package-lock.json"),
		`{"lockfileVersion":3,"packages":{`+
			`"node_modules/event-stream":{"version":"3.3.6","dependencies":{"flatmap-stream":"0.1.1"}},`+
			`"node_modules/flatmap-stream":{"version":"0.1.1"}}}`)
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
		t.Errorf("transitively-reachable dep should be P2, got %+v", fm)
	} else if len(fm.Via) < 2 || fm.Via[0] != "event-stream" || fm.Via[len(fm.Via)-1] != "flatmap-stream" {
		t.Errorf("P2 transitive dep should carry via path event-stream → flatmap-stream, got via=%v", fm.Via)
	}
	log4 := deepOf(rep, "CVE-2021-44228")
	if log4 == nil || log4.Priority != 1 || log4.Kind != "cve-pattern" {
		t.Errorf("a present CVE code pattern should be P1, got %+v", log4)
	}
	if rep.P1Count < 2 || rep.P2Count < 1 {
		t.Errorf("counts off: P1=%d P2=%d", rep.P1Count, rep.P2Count)
	}
	// All P1 findings must sort ahead of every lower-priority finding.
	lastP1 := -1
	for i, f := range rep.Findings {
		if f.Priority == 1 {
			lastP1 = i
		}
	}
	for i, f := range rep.Findings {
		if f.Priority > 1 && i < lastP1 {
			t.Errorf("a P%d finding at %d precedes a P1 finding at %d", f.Priority, i, lastP1)
		}
	}
}

// TestDeepScanUnreachableDepIsP3 covers the DQ-H.3 third tier: when the npm
// dependency graph IS analyzable (a lockfile is present and source imports at
// least one package) and a flagged package has no import path from first-party
// code, it is demoted to P3 unreachable — distinct from a P2 whose ecosystem
// graph was never analyzed.
func TestDeepScanUnreachableDepIsP3(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	mkProjFile(t, filepath.Join(dir, "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"node_modules/event-stream":{"version":"3.3.6"}}}`)
	// Source imports an unrelated package, so the graph is analyzed with a real
	// root — but event-stream is reachable from nothing.
	mkProjFile(t, filepath.Join(dir, "src", "app.js"), "import _ from 'lodash';\n")

	rep, err := lib.DeepScan(dir)
	if err != nil {
		t.Fatalf("DeepScan: %v", err)
	}
	es := deepOf(rep, "event-stream")
	if es == nil || es.Priority != 3 {
		t.Errorf("unreachable flagged dep (graph analyzed, no path) should be P3, got %+v", es)
	}
	if rep.P3Count < 1 {
		t.Errorf("p3_unreachable_count should be >=1, got %d", rep.P3Count)
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
