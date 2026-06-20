package tools

import (
	"os"
	"path/filepath"
	"testing"
)

// newOverlayTestLibrary builds a minimal library root (empty curated
// malicious DB) plus an overlay file at the returned path, then returns
// a Library wired to that overlay via WithOverlayPaths.
func newOverlayTestLibrary(t *testing.T, overlayJSON string) *Library {
	t.Helper()
	tmp := t.TempDir()
	must := func(p, body string) {
		full := filepath.Join(tmp, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	must("vulnerabilities/supply-chain/malicious-packages/npm.json", `{"ecosystem":"npm","entries":[]}`)
	overlayPath := filepath.Join(tmp, ".skills-check", "overlay.json")
	if overlayJSON != "" {
		must(".skills-check/overlay.json", overlayJSON)
	}
	lib, err := NewLibrary(tmp, WithOverlayPaths(overlayPath))
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	return lib
}

// TestOverlayBlocksPackage is the core LEARN-loop assertion: a package
// recorded in the local overlay is flagged by LookupVulnerability (and
// therefore by check/scan/gate) exactly like a curated malicious row.
func TestOverlayBlocksPackage(t *testing.T) {
	lib := newOverlayTestLibrary(t, `{
		"schema_version": "1.0",
		"malicious_packages": [
			{"name": "evil-pkg", "ecosystem": "npm", "severity": "critical", "reason": "exfiltrates env vars"}
		]
	}`)
	res, err := lib.LookupVulnerability("evil-pkg", "npm", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Matches) != 1 {
		t.Fatalf("got %d matches, want 1 overlay match", len(res.Matches))
	}
	m := res.Matches[0]
	if m.Source != OverlaySource {
		t.Errorf("Source = %q, want %q", m.Source, OverlaySource)
	}
	if m.Severity != "critical" {
		t.Errorf("Severity = %q, want critical", m.Severity)
	}

	// A package NOT in the overlay stays clean.
	clean, err := lib.LookupVulnerability("fine-pkg", "npm", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(clean.Matches) != 0 {
		t.Errorf("unrelated package got %d matches, want 0", len(clean.Matches))
	}
}

// TestOverlayDefaultsBlockAllVersions verifies an entry with no
// versions_affected applies to every version (the safe default for a
// freshly-recorded block).
func TestOverlayDefaultsBlockAllVersions(t *testing.T) {
	lib := newOverlayTestLibrary(t, `{
		"malicious_packages": [{"name": "broad", "ecosystem": "npm"}]
	}`)
	for _, v := range []string{"1.0.0", "9.9.9", ""} {
		res, err := lib.LookupVulnerability("broad", "npm", v)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Matches) != 1 {
			t.Errorf("version %q: got %d matches, want 1 (default = all versions)", v, len(res.Matches))
		}
	}
}

// TestOverlayVersionRange verifies version_affected narrowing: only the
// listed version is blocked.
func TestOverlayVersionRange(t *testing.T) {
	lib := newOverlayTestLibrary(t, `{
		"malicious_packages": [{"name": "narrow", "ecosystem": "npm", "versions_affected": ["1.0.0"]}]
	}`)
	hit, _ := lib.LookupVulnerability("narrow", "npm", "1.0.0")
	if len(hit.Matches) != 1 {
		t.Errorf("blocked version: got %d matches, want 1", len(hit.Matches))
	}
	miss, _ := lib.LookupVulnerability("narrow", "npm", "2.0.0")
	if len(miss.Matches) != 0 {
		t.Errorf("unaffected version: got %d matches, want 0", len(miss.Matches))
	}
}

// TestOverlayFlowsToScanner confirms the overlay match surfaces through
// the ScanDependencies path (the one gate uses) with the honest "high"
// confidence band for a user-asserted block.
func TestOverlayFlowsToScanner(t *testing.T) {
	lib := newOverlayTestLibrary(t, `{
		"malicious_packages": [{"name": "left-pad", "ecosystem": "npm", "reason": "test block"}]
	}`)
	// Write a package.json into the library tmp so the scanner can read
	// it (allowed-roots includes the library root by default).
	manifestPath := filepath.Join(lib.root, "package.json")
	if err := os.WriteFile(manifestPath, []byte(`{"dependencies":{"left-pad":"1.3.0"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := lib.ScanDependencies(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var found *DependencyFinding
	for i := range res.Findings {
		if res.Findings[i].Package == "left-pad" && res.Findings[i].Category == "malicious-package" {
			found = &res.Findings[i]
		}
	}
	if found == nil {
		t.Fatalf("overlay block did not surface in ScanDependencies: %+v", res.Findings)
	}
	if found.Confidence != "high" {
		t.Errorf("overlay finding confidence = %q, want high (user-asserted, not central canon)", found.Confidence)
	}
}

// TestOverlayLaterPathWins confirms a project-local overlay overrides a
// user-global one on a (name, ecosystem) collision.
func TestOverlayLaterPathWins(t *testing.T) {
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "vulnerabilities", "supply-chain", "malicious-packages", "npm.json"), nil, 0o644); err != nil {
		// directory may not exist yet
		_ = os.MkdirAll(filepath.Join(tmp, "vulnerabilities", "supply-chain", "malicious-packages"), 0o755)
		_ = os.WriteFile(filepath.Join(tmp, "vulnerabilities", "supply-chain", "malicious-packages", "npm.json"), []byte(`{"ecosystem":"npm","entries":[]}`), 0o644)
	}
	global := filepath.Join(tmp, "global.json")
	local := filepath.Join(tmp, "local.json")
	os.WriteFile(global, []byte(`{"malicious_packages":[{"name":"x","ecosystem":"npm","severity":"low"}]}`), 0o644)
	os.WriteFile(local, []byte(`{"malicious_packages":[{"name":"x","ecosystem":"npm","severity":"critical"}]}`), 0o644)
	// Order: global first, local second -> local wins.
	lib, err := NewLibrary(tmp, WithOverlayPaths(global, local))
	if err != nil {
		t.Fatal(err)
	}
	res, _ := lib.LookupVulnerability("x", "npm", "1.0.0")
	if len(res.Matches) != 1 || res.Matches[0].Severity != "critical" {
		t.Errorf("later path should win: got %+v", res.Matches)
	}
}
