package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCorpus drops a minimal eval corpus at <root>/skills/<id>/evals/cases.json.
func writeCorpus(t *testing.T, root, id, body string) {
	t.Helper()
	dir := filepath.Join(root, "skills", id, "evals")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cases.json"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The signature oracle needs no rule data, so it exercises the whole
// load → judge → summarise path against a temp library.
func TestRunSkillEvalSignatureOracle(t *testing.T) {
	root := t.TempDir()
	writeCorpus(t, root, "demo", `{
      "schema_version": "1.0",
      "skill_id": "demo",
      "min_lift": 0.5,
      "cases": [
        { "id": "interp", "oracle": "signature",
          "insecure_signature": "SELECT[^;]*\\$\\{[^}]*req",
          "baseline": "const q = `+"`SELECT * FROM t WHERE id = ${req.query.id}`"+`;",
          "with_skill": "db.query('SELECT * FROM t WHERE id = $1', [req.query.id]);" },
        { "id": "concat", "oracle": "signature",
          "insecure_signature": "SELECT[^;]*\\$\\{[^}]*req",
          "baseline": "const q = `+"`SELECT * FROM t WHERE n = ${req.body.n}`"+`;",
          "with_skill": "db.query('SELECT * FROM t WHERE n = $1', [req.body.n]);" }
      ]
    }`)

	res, err := runSkillEval(root, "demo", "high", 0.25)
	if err != nil {
		t.Fatalf("runSkillEval: %v", err)
	}
	if res.Summary.Cases != 2 {
		t.Fatalf("cases = %d, want 2", res.Summary.Cases)
	}
	if res.Summary.BaselineInsecure != 2 {
		t.Errorf("baseline_insecure = %d, want 2", res.Summary.BaselineInsecure)
	}
	if res.Summary.WithSkillInsecure != 0 {
		t.Errorf("with_skill_insecure = %d, want 0", res.Summary.WithSkillInsecure)
	}
	if res.Summary.PreventionLift != 1.0 {
		t.Errorf("prevention_lift = %v, want 1.0", res.Summary.PreventionLift)
	}
	if !res.Summary.Pass {
		t.Errorf("expected pass=true, got status %q", res.status)
	}
	if res.Oracle != "signature" {
		t.Errorf("oracle = %q, want signature", res.Oracle)
	}
}

// A corpus where the skill makes no difference must not pass: zero lift
// is a FAIL below the floor, not a green check.
func TestRunSkillEvalNoLiftFails(t *testing.T) {
	root := t.TempDir()
	writeCorpus(t, root, "noop", `{
      "schema_version": "1.0", "skill_id": "noop", "min_lift": 0.5,
      "cases": [
        { "id": "still-bad", "oracle": "signature",
          "insecure_signature": "SELECT[^;]*\\$\\{[^}]*req",
          "baseline": "const q = `+"`SELECT ${req.x}`"+`;",
          "with_skill": "const q = `+"`SELECT ${req.x}`"+`;" }
      ]
    }`)

	res, err := runSkillEval(root, "noop", "high", 0.25)
	if err != nil {
		t.Fatalf("runSkillEval: %v", err)
	}
	if res.Summary.PreventionLift != 0 {
		t.Errorf("prevention_lift = %v, want 0", res.Summary.PreventionLift)
	}
	if res.Summary.Pass {
		t.Errorf("expected pass=false for zero-lift corpus")
	}
}

// A corpus whose baseline is already secure can't measure prevention and
// must surface a WARN, not a misleading pass.
func TestRunSkillEvalNoInsecureBaselineWarns(t *testing.T) {
	root := t.TempDir()
	writeCorpus(t, root, "clean", `{
      "schema_version": "1.0", "skill_id": "clean",
      "cases": [
        { "id": "safe", "oracle": "signature",
          "insecure_signature": "SELECT[^;]*\\$\\{[^}]*req",
          "baseline": "db.query('SELECT 1', []);",
          "with_skill": "db.query('SELECT 1', []);" }
      ]
    }`)

	res, err := runSkillEval(root, "clean", "high", 0.25)
	if err != nil {
		t.Fatalf("runSkillEval: %v", err)
	}
	if res.Summary.Pass {
		t.Errorf("expected pass=false when baseline has nothing insecure")
	}
	if res.status != "WARN: no insecure baseline" {
		t.Errorf("status = %q, want WARN", res.status)
	}
}
