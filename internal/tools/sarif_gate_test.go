package tools

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestPolicyCheckSARIFDirty drives a failing gate (a Dockerfile with
// FROM :latest + USER root) through PolicyCheck and asserts the SARIF
// wrapper is well-formed: one run, the gate driver name, at least one
// result, and every result's RuleIndex pointing at a real rule.
func TestPolicyCheckSARIFDirty(t *testing.T) {
	lib := newLibrary(t)
	dirty := writeTempFile(t, "Dockerfile", "FROM node:latest\nUSER root\n")
	res, err := lib.PolicyCheck(dirty, "high")
	if err != nil {
		t.Fatalf("PolicyCheck(dirty): %v", err)
	}
	if res.Pass {
		t.Fatalf("precondition: dirty Dockerfile should fail the gate")
	}

	log := PolicyCheckSARIF([]*PolicyCheckResult{res})
	if log.Version != SARIFVersion {
		t.Errorf("version = %q, want %q", log.Version, SARIFVersion)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected one run, got %d", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != SARIFGateToolName {
		t.Errorf("driver name = %q, want %q", run.Tool.Driver.Name, SARIFGateToolName)
	}
	if len(run.Results) == 0 {
		t.Fatalf("expected at least one SARIF result for a failing gate")
	}
	for i, r := range run.Results {
		if r.RuleID == "" {
			t.Errorf("result %d: empty ruleId", i)
		}
		if r.RuleIndex < 0 || r.RuleIndex >= len(run.Tool.Driver.Rules) {
			t.Errorf("result %d: ruleIndex %d out of range (%d rules)", i, r.RuleIndex, len(run.Tool.Driver.Rules))
			continue
		}
		if got := run.Tool.Driver.Rules[r.RuleIndex].ID; got != r.RuleID {
			t.Errorf("result %d: ruleIndex points at %q, want %q", i, got, r.RuleID)
		}
		if r.Level == "" {
			t.Errorf("result %d: empty level", i)
		}
	}
}

// TestPolicyCheckSARIFClean verifies a passing gate still produces a
// well-formed SARIF log, and crucially that rules/results serialise as
// `[]` rather than `null` — GitHub Advanced Security rejects the null
// form on ingest.
func TestPolicyCheckSARIFClean(t *testing.T) {
	lib := newLibrary(t)
	clean := writeTempFile(t, "Dockerfile", "FROM node:20-alpine@sha256:abc\nUSER 10001\n")
	res, err := lib.PolicyCheck(clean, "high")
	if err != nil {
		t.Fatalf("PolicyCheck(clean): %v", err)
	}
	if !res.Pass {
		t.Fatalf("precondition: clean Dockerfile should pass the gate")
	}

	log := PolicyCheckSARIF([]*PolicyCheckResult{res})
	raw, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte(`"results":null`)) {
		t.Errorf("results serialised as null; want []")
	}
	if bytes.Contains(raw, []byte(`"rules":null`)) {
		t.Errorf("rules serialised as null; want []")
	}

	// Round-trip back into the struct to confirm the document is valid.
	var back SARIFLog
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if len(back.Runs) != 1 || back.Runs[0].Tool.Driver.Name != SARIFGateToolName {
		t.Errorf("round-trip lost run/driver identity: %+v", back.Runs)
	}
}

// TestPolicyCheckSARIFMultiFile confirms that several PolicyCheckResults
// (one gate invocation over multiple files) aggregate into a single run
// with deduplicated rules and correctly re-anchored RuleIndex values.
func TestPolicyCheckSARIFMultiFile(t *testing.T) {
	lib := newLibrary(t)
	dirty := writeTempFile(t, "Dockerfile", "FROM node:latest\nUSER root\n")
	clean := writeTempFile(t, "clean.txt", "nothing to see here\n")

	dirtyRes, err := lib.PolicyCheck(dirty, "high")
	if err != nil {
		t.Fatalf("PolicyCheck(dirty): %v", err)
	}
	cleanRes, err := lib.PolicyCheck(clean, "high")
	if err != nil {
		t.Fatalf("PolicyCheck(clean): %v", err)
	}

	log := PolicyCheckSARIF([]*PolicyCheckResult{dirtyRes, cleanRes})
	if len(log.Runs) != 1 {
		t.Fatalf("multi-file should still be one run, got %d", len(log.Runs))
	}
	rules := log.Runs[0].Tool.Driver.Rules

	// Rules must be unique by ID and sorted ascending.
	seen := map[string]bool{}
	for i, r := range rules {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %q in driver.rules", r.ID)
		}
		seen[r.ID] = true
		if i > 0 && rules[i-1].ID > r.ID {
			t.Errorf("rules not sorted: %q before %q", rules[i-1].ID, r.ID)
		}
	}
	// Every result must still resolve to its rule after the sort.
	for i, res := range log.Runs[0].Results {
		if rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %d: ruleIndex %d -> %q, want %q", i, res.RuleIndex, rules[res.RuleIndex].ID, res.RuleID)
		}
	}
}

// TestPolicyCheckSARIFEmptyInput guards the degenerate case: no results
// at all must still yield a valid log with empty (non-null) arrays.
func TestPolicyCheckSARIFEmptyInput(t *testing.T) {
	log := PolicyCheckSARIF(nil)
	raw, err := json.Marshal(log)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(raw, []byte("null")) {
		t.Errorf("empty-input SARIF contains null: %s", raw)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("expected one run even for empty input, got %d", len(log.Runs))
	}
}
