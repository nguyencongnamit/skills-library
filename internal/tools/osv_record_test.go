package tools

import (
	"os"
	"path/filepath"
	"testing"
)

// newOSVTestLibrary builds a synthetic library root holding a single
// pypi OSV advisory for `requests` whose affected range is
// [introduced=2.3.0, fixed=2.31.0). It returns the constructed Library.
func newOSVTestLibrary(t *testing.T) *Library {
	t.Helper()
	tmp := t.TempDir()
	mustMkdir := func(p string) {
		if err := os.MkdirAll(filepath.Join(tmp, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite := func(p, body string) {
		if err := os.WriteFile(filepath.Join(tmp, p), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustMkdir("skills")
	mustMkdir("vulnerabilities/supply-chain/malicious-packages")
	mustMkdir("vulnerabilities/osv/pypi")
	mustWrite("vulnerabilities/supply-chain/malicious-packages/pypi.json",
		`{"ecosystem":"pypi","entries":[]}`)
	mustWrite("vulnerabilities/osv/pypi/GHSA-req.json", `{
		"id": "GHSA-req",
		"summary": "requests leaks Proxy-Authorization on redirect",
		"affected": [
			{
				"package": {"name": "requests", "ecosystem": "PyPI"},
				"ranges": [
					{"type": "ECOSYSTEM", "events": [
						{"introduced": "2.3.0"},
						{"fixed": "2.31.0"}
					]}
				]
			}
		]
	}`)
	mustWrite("vulnerabilities/osv/pypi/index.json", `{
		"schema_version": "1.0",
		"by_package": {
			"requests": [
				{"id":"GHSA-req","file":"GHSA-req.json","summary":"x","aliases":[],"severity":"high"}
			]
		}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	return lib
}

// TestLookupOSVVersionRangeFiltering is the regression test for the
// scanner-eval FP: requests pinned to the FIXED version (2.31.0) must
// not be flagged for the [2.3.0, 2.31.0) advisory, a vulnerable version
// in range must be flagged and version-confirmed, and an empty version
// must preserve the name-only behaviour.
func TestLookupOSVVersionRangeFiltering(t *testing.T) {
	lib := newOSVTestLibrary(t)

	cases := []struct {
		name          string
		version       string
		wantLen       int
		wantConfirmed bool
	}{
		{"fixed version is dropped", "2.31.0", 0, false},
		{"newer than fixed is dropped", "2.32.0", 0, false},
		{"in-range version is confirmed", "2.20.0", 1, true},
		{"introduced boundary is in range", "2.3.0", 1, true},
		{"below introduced is dropped", "2.2.0", 0, false},
		{"empty version keeps name match unconfirmed", "", 1, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := lib.lookupOSV("pypi", "requests", c.version)
			if len(got) != c.wantLen {
				t.Fatalf("lookupOSV(requests@%q): got %d advisories, want %d", c.version, len(got), c.wantLen)
			}
			if c.wantLen == 1 && got[0].VersionConfirmed != c.wantConfirmed {
				t.Errorf("lookupOSV(requests@%q): VersionConfirmed=%v, want %v", c.version, got[0].VersionConfirmed, c.wantConfirmed)
			}
		})
	}
}

// TestLookupOSVFailsOpenOnUnevaluableRecord verifies the conservative
// stance: when the affected ranges cannot be evaluated for the
// ecosystem (here a GIT range with commit-hash events), the advisory is
// kept rather than dropped, and left version-unconfirmed.
func TestLookupOSVFailsOpenOnUnevaluableRecord(t *testing.T) {
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
	must("vulnerabilities/supply-chain/malicious-packages/pypi.json", `{"ecosystem":"pypi","entries":[]}`)
	must("vulnerabilities/osv/pypi/GHSA-git.json", `{
		"id": "GHSA-git",
		"summary": "only a GIT range",
		"affected": [
			{"package": {"name": "somepkg", "ecosystem": "PyPI"},
			 "ranges": [{"type": "GIT", "events": [{"introduced": "abc123"}, {"fixed": "def456"}]}]}
		]
	}`)
	must("vulnerabilities/osv/pypi/index.json", `{
		"schema_version": "1.0",
		"by_package": {"somepkg": [{"id":"GHSA-git","file":"GHSA-git.json","summary":"x","aliases":[],"severity":"high"}]}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	got := lib.lookupOSV("pypi", "somepkg", "1.0.0")
	if len(got) != 1 {
		t.Fatalf("fail-open: got %d advisories, want 1 (unevaluable record must be kept)", len(got))
	}
	if got[0].VersionConfirmed {
		t.Errorf("fail-open: VersionConfirmed should be false for an unevaluable record")
	}
}

// TestOSVExplicitVersionsList checks that the explicit affected-versions
// enumeration is honoured even when no ranges are present.
func TestOSVExplicitVersionsList(t *testing.T) {
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
	must("vulnerabilities/supply-chain/malicious-packages/pypi.json", `{"ecosystem":"pypi","entries":[]}`)
	must("vulnerabilities/osv/pypi/GHSA-list.json", `{
		"id": "GHSA-list",
		"summary": "enumerated versions only",
		"affected": [
			{"package": {"name": "listpkg", "ecosystem": "PyPI"}, "versions": ["1.0.0", "1.1.0"]}
		]
	}`)
	must("vulnerabilities/osv/pypi/index.json", `{
		"schema_version": "1.0",
		"by_package": {"listpkg": [{"id":"GHSA-list","file":"GHSA-list.json","summary":"x","aliases":[],"severity":"high"}]}
	}`)
	lib, err := NewLibrary(tmp)
	if err != nil {
		t.Fatalf("NewLibrary: %v", err)
	}
	if got := lib.lookupOSV("pypi", "listpkg", "1.1.0"); len(got) != 1 || !got[0].VersionConfirmed {
		t.Errorf("enumerated hit: got %+v, want one version-confirmed advisory", got)
	}
	if got := lib.lookupOSV("pypi", "listpkg", "2.0.0"); len(got) != 0 {
		t.Errorf("version absent from enumeration must be dropped: got %+v", got)
	}
}
