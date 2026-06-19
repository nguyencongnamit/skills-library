package tools

import "strings"

// rule_cwe.go is the single source of truth that maps a detection rule to the
// CWE weakness(es) it surfaces (DQ.2). Every SARIF emitter consults it so a
// finding self-describes its CWE — which is what lets a real scan result feed
// the CF.7 cross-framework spine (finding -> CWE -> controls -> skills ->
// checks) without a human re-typing the identifier.
//
// Values for the container/dependency rules are taken from the authoritative
// per-rule `cwe:` in the hardening checklists and the check registry; the
// CI-pipeline rules (GitHub Actions / GitLab CI), which have no checklist CWE,
// are mapped here from each rule's detection semantics. Keys are the bare rule
// IDs (the SARIF "skills-mcp." / "skills-mcp.dlp." / "skills-mcp.secret."
// prefixes are stripped by cweForRuleID before lookup).
var ruleCWE = map[string][]string{
	// Dependency scan categories (scan_dependencies / check_dependency).
	"malicious-package": {"CWE-1104", "CWE-506"},
	"typosquat":         {"CWE-1357"},
	"cve-pattern":       {"CWE-937"},

	// Dockerfile hardening (scan_dockerfile) — from dockerfile_hardening.yaml.
	"dkr-pinned-base-digest":       {"CWE-1357"},
	"dkr-non-root-user":            {"CWE-250"},
	"dkr-missing-user-directive":   {"CWE-250"},
	"dkr-no-secrets-in-env":        {"CWE-798"},
	"dkr-no-secrets-in-build-args": {"CWE-798"},
	"dkr-no-curl-pipe-sh":          {"CWE-829"},
	"dkr-no-add-remote":            {"CWE-494"},
	"dkr-apt-version-pin":          {"CWE-1357"},
	"dkr-explicit-latest-tag":      {"CWE-1357"},
	"dkr-eol-base-image":           {"CWE-1104"},

	// Kubernetes pod-security (scan_dockerfile k8s manifests) — from k8s_pod_security.yaml.
	"k8s-run-as-non-root":         {"CWE-250"},
	"k8s-drop-all-capabilities":   {"CWE-269"},
	"k8s-no-privileged":           {"CWE-269"},
	"k8s-no-default-sa":           {"CWE-250"},
	"k8s-network-policy-deny-all": {"CWE-284"},
	"k8s-rbac-least-privilege":    {"CWE-269"},
	"k8s-image-digest-pin":        {"CWE-1357"},

	// GitHub Actions hardening (scan_github_actions) — mapped from semantics.
	"gha-pin-actions-by-sha":              {"CWE-829"},
	"gha-default-permissions-read":        {"CWE-272"},
	"gha-no-untrusted-script-injection":   {"CWE-94"},
	"gha-pr-target-no-untrusted-checkout": {"CWE-94"},
	"gha-oidc-cloud-credentials":          {"CWE-522"},
	"gha-no-curl-pipe-bash":               {"CWE-494"},
	"gha-harden-runner":                   {"CWE-829"},
	"gha-cache-key-scope":                 {"CWE-349"},
	"gha-artifact-verify-source":          {"CWE-345"},
	"gha-ast-expression-injection":        {"CWE-94"},
	"gha-ast-pwn-request":                 {"CWE-94"},
	"gha-ast-unpinned-action":             {"CWE-829"},

	// GitLab CI hardening (scan_github_actions sibling rules).
	"glci-no-curl-pipe-bash":        {"CWE-494"},
	"glci-no-shell-injection":       {"CWE-94"},
	"glci-pin-include-sha":          {"CWE-829"},
	"glci-protected-variables":      {"CWE-522"},
	"glci-runner-isolation":         {"CWE-1357"},
	"glci-signed-commits":           {"CWE-345"},
	"glci-merge-request-no-secrets": {"CWE-798"},
}

// secretCWE is the weakness set every secret-detection finding surfaces:
// hard-coded credentials and cleartext storage of sensitive data.
var secretCWE = []string{"CWE-798", "CWE-312"}

// cweForRuleID returns the CWE identifier(s) a rule surfaces, or nil if the
// rule has no mapped weakness (e.g. "scan-error"). It accepts either a bare
// rule ID or a SARIF rule ID carrying the "skills-mcp." prefix; secret rules
// (the "dlp." / "secret." families) all map to the secret weakness set.
func cweForRuleID(id string) []string {
	id = strings.TrimPrefix(id, "skills-mcp.")
	if strings.HasPrefix(id, "dlp.") || strings.HasPrefix(id, "secret.") {
		return secretCWE
	}
	return ruleCWE[id]
}

// cweTags renders CWE identifiers as the tag strings GitHub code scanning and
// other SARIF consumers recognise (e.g. "external/cwe/cwe-798"), prefixed with
// a generic "security" tag.
func cweTags(cwes []string) []string {
	out := make([]string, 0, len(cwes)+1)
	out = append(out, "security")
	for _, c := range cwes {
		out = append(out, "external/cwe/"+strings.ToLower(c))
	}
	return out
}

// annotateRuleCWE stamps each rule with its CWE(s) — properties.cwe (machine
// readable) plus the external/cwe/* tags — and returns the sorted union of all
// CWEs seen, for the run-level taxonomy. Rules with no mapped CWE are left
// untouched. Safe to call after the rules slice is in its final order.
func annotateRuleCWE(rules []SARIFRule) []string {
	seen := map[string]bool{}
	for i := range rules {
		cwes := cweForRuleID(rules[i].ID)
		if len(cwes) == 0 {
			continue
		}
		if rules[i].Properties == nil {
			rules[i].Properties = map[string]any{}
		}
		rules[i].Properties["cwe"] = cwes
		tags := cweTags(cwes)
		if existing, ok := rules[i].Properties["tags"].([]string); ok {
			tags = append(append([]string{}, existing...), tags...)
		}
		rules[i].Properties["tags"] = tags
		for _, c := range cwes {
			seen[c] = true
		}
	}
	return sortedKeys(seen)
}

// cweTaxonomy builds the run-level CWE taxonomy from a (sorted) CWE set, or
// nil when the run referenced no CWE.
func cweTaxonomy(cwes []string) []SARIFTaxonomy {
	if len(cwes) == 0 {
		return nil
	}
	taxa := make([]SARIFTaxon, 0, len(cwes))
	for _, c := range cwes {
		taxa = append(taxa, SARIFTaxon{ID: c})
	}
	return []SARIFTaxonomy{{Name: "CWE", Taxa: taxa}}
}

// sarifLogWithCWE assembles the final SARIF document for an emitter: it stamps
// each rule with its CWE (DQ.2) and attaches the run-level CWE taxonomy, then
// builds the single-run log every skills-mcp scanner emits. Centralising the
// run construction keeps the driver identity and CWE annotation identical
// across every emitter.
func sarifLogWithCWE(rules []SARIFRule, results []SARIFResult) *SARIFLog {
	cwes := annotateRuleCWE(rules)
	return &SARIFLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []SARIFRun{{
			Tool: SARIFTool{Driver: SARIFDriver{
				Name:           SARIFToolName,
				InformationURI: "https://github.com/namncqualgo/skills-library",
				Rules:          rules,
			}},
			Results:    results,
			Taxonomies: cweTaxonomy(cwes),
		}},
	}
}
