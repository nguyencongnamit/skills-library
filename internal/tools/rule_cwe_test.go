package tools

import (
	"reflect"
	"testing"
)

func TestCWEForRuleID(t *testing.T) {
	cases := map[string][]string{
		// bare ids
		"dkr-non-root-user":            {"CWE-250"},
		"gha-ast-expression-injection": {"CWE-94"},
		"typosquat":                    {"CWE-1357"},
		"malicious-package":            {"CWE-1104", "CWE-506"},
		// skills-mcp.-prefixed ids (the SARIF form)
		"skills-mcp.dkr-no-curl-pipe-sh": {"CWE-829"},
		"skills-mcp.cve-pattern":         {"CWE-937"},
		// secret families (both prefixes) collapse to the secret weakness set
		"skills-mcp.dlp.aws-secret-access-key": {"CWE-798", "CWE-312"},
		"skills-mcp.secret.github-pat":         {"CWE-798", "CWE-312"},
	}
	for id, want := range cases {
		if got := cweForRuleID(id); !reflect.DeepEqual(got, want) {
			t.Errorf("cweForRuleID(%q) = %v, want %v", id, got, want)
		}
	}
	// Unmapped rules (e.g. the scan-error sentinel) carry no CWE.
	for _, id := range []string{"scan-error", "skills-mcp.scan-error", "no-such-rule"} {
		if got := cweForRuleID(id); got != nil {
			t.Errorf("cweForRuleID(%q) = %v, want nil", id, got)
		}
	}
}

func TestCWETags(t *testing.T) {
	got := cweTags([]string{"CWE-798", "CWE-312"})
	want := []string{"security", "external/cwe/cwe-798", "external/cwe/cwe-312"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("cweTags = %v, want %v", got, want)
	}
}

func TestAnnotateRuleCWEAndTaxonomy(t *testing.T) {
	rules := []SARIFRule{
		{ID: "skills-mcp.dkr-non-root-user"},
		{ID: "skills-mcp.malicious-package"},
		{ID: "skills-mcp.dlp.aws-secret-access-key"},
		{ID: "skills-mcp.scan-error"}, // no CWE — must be left untouched
	}
	union := annotateRuleCWE(rules)

	// dkr rule got its CWE + tags.
	props := rules[0].Properties
	if props == nil || !reflect.DeepEqual(props["cwe"], []string{"CWE-250"}) {
		t.Errorf("dkr rule cwe = %v, want [CWE-250]", props["cwe"])
	}
	tags, _ := props["tags"].([]string)
	if !contains(tags, "external/cwe/cwe-250") {
		t.Errorf("dkr rule tags missing external/cwe/cwe-250: %v", tags)
	}
	// scan-error rule untouched.
	if rules[3].Properties != nil {
		t.Errorf("scan-error rule must have no properties, got %v", rules[3].Properties)
	}
	// Union is sorted + de-duplicated across all annotated rules.
	wantUnion := []string{"CWE-1104", "CWE-250", "CWE-312", "CWE-506", "CWE-798"}
	if !reflect.DeepEqual(union, wantUnion) {
		t.Errorf("union = %v, want %v", union, wantUnion)
	}

	// The taxonomy mirrors the union.
	tax := cweTaxonomy(union)
	if len(tax) != 1 || tax[0].Name != "CWE" || len(tax[0].Taxa) != len(wantUnion) {
		t.Fatalf("unexpected taxonomy: %+v", tax)
	}
	if cweTaxonomy(nil) != nil {
		t.Error("cweTaxonomy(nil) must be nil")
	}
}

// TestScanSecretsSARIFCarriesCWE is the end-to-end DQ.2 check: a secret
// finding's SARIF rule must carry its CWE (properties.cwe + external/cwe tag)
// and the run must expose the CWE taxonomy, so the finding can feed the CF.7
// spine without a human re-typing the identifier.
func TestScanSecretsSARIFCarriesCWE(t *testing.T) {
	res := &ScanSecretsResult{
		FilePath: "/tmp/config.js",
		Matches:  []SecretMatch{{Name: "aws-secret-access-key", Severity: "high", Start: 0, End: 10}},
	}
	log := ScanSecretsSARIF(res)
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) == 0 {
		t.Fatal("expected at least one rule")
	}
	rule := run.Tool.Driver.Rules[0]
	if !reflect.DeepEqual(rule.Properties["cwe"], []string{"CWE-798", "CWE-312"}) {
		t.Errorf("rule cwe = %v, want [CWE-798 CWE-312]", rule.Properties["cwe"])
	}
	var sawCWETaxon bool
	for _, tax := range run.Taxonomies {
		if tax.Name == "CWE" && len(tax.Taxa) > 0 {
			sawCWETaxon = true
		}
	}
	if !sawCWETaxon {
		t.Error("expected a populated CWE taxonomy on the run")
	}
}
