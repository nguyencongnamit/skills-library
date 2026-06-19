package tools

import (
	"sort"
	"testing"
)

func TestNormalizeCWE(t *testing.T) {
	ok := map[string]string{
		"CWE-79":   "CWE-79",
		"cwe-79":   "CWE-79",
		"79":       "CWE-79",
		"  79  ":   "CWE-79",
		"CWE-1104": "CWE-1104",
	}
	for in, want := range ok {
		got, err := NormalizeCWE(in)
		if err != nil {
			t.Errorf("NormalizeCWE(%q) errored: %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizeCWE(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "abc", "CWE-", "CWE-xyz", "79-80", "CWE 79"} {
		if _, err := NormalizeCWE(bad); err == nil {
			t.Errorf("NormalizeCWE(%q) should have errored", bad)
		}
	}
}

func TestMapCWESpine(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.MapCWE("798") // bare number → CWE-798 (hardcoded credentials)
	if err != nil {
		t.Fatalf("MapCWE: %v", err)
	}
	if res.CWE != "CWE-798" {
		t.Errorf("CWE = %q, want CWE-798", res.CWE)
	}
	if res.ControlCount == 0 || len(res.Frameworks) == 0 {
		t.Fatalf("expected CWE-798 to map to controls across frameworks, got %+v", res)
	}

	// The spine must join the weakness to the prevention skill and the
	// runnable checks that detect it.
	if !contains(res.Skills, "secret-detection") {
		t.Errorf("expected secret-detection in skills, got %v", res.Skills)
	}
	for _, want := range []string{"scan_secrets", "check_secret_pattern"} {
		if !contains(res.Checks, want) {
			t.Errorf("expected %q in checks, got %v", want, res.Checks)
		}
	}

	// ControlCount must equal the sum of per-framework controls, and the
	// skills/checks unions must be sorted and de-duplicated.
	sum := 0
	for _, fm := range res.Frameworks {
		sum += len(fm.Controls)
	}
	if sum != res.ControlCount {
		t.Errorf("ControlCount %d != sum of framework controls %d", res.ControlCount, sum)
	}
	assertSortedUnique(t, "skills", res.Skills)
	assertSortedUnique(t, "checks", res.Checks)
}

func TestMapCWEUnknownIsEmptyNotError(t *testing.T) {
	lib := newLibrary(t)
	res, err := lib.MapCWE("CWE-9999999")
	if err != nil {
		t.Fatalf("a well-formed but unmapped CWE must not error: %v", err)
	}
	if res.ControlCount != 0 || len(res.Frameworks) != 0 {
		t.Errorf("unmapped CWE should yield no controls, got %+v", res)
	}
	// Slices must marshal as [] not null.
	if res.Skills == nil || res.Checks == nil {
		t.Error("Skills/Checks must be non-nil (empty) slices")
	}
}

func TestMapCWEInvalidErrors(t *testing.T) {
	lib := newLibrary(t)
	if _, err := lib.MapCWE("not-a-cwe"); err == nil {
		t.Error("MapCWE must reject a malformed CWE")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func assertSortedUnique(t *testing.T, label string, s []string) {
	t.Helper()
	if !sort.StringsAreSorted(s) {
		t.Errorf("%s not sorted: %v", label, s)
	}
	seen := map[string]bool{}
	for _, v := range s {
		if seen[v] {
			t.Errorf("%s has duplicate %q", label, v)
		}
		seen[v] = true
	}
}
