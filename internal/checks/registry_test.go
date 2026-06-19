package checks

import (
	"regexp"
	"sort"
	"testing"
)

func TestIsKnownAndLookup(t *testing.T) {
	if !IsKnown("scan_dependencies") {
		t.Error("scan_dependencies should be a known check")
	}
	if IsKnown("no_such_check") {
		t.Error("no_such_check must not be known")
	}
	c, ok := Lookup("scan_secrets")
	if !ok {
		t.Fatal("Lookup(scan_secrets) should succeed")
	}
	if c.ID != "scan_secrets" || c.Kind != KindScanner {
		t.Errorf("unexpected check for scan_secrets: %+v", c)
	}
	if _, ok := Lookup("nope"); ok {
		t.Error("Lookup of an unknown ID must report ok=false")
	}
}

func TestAllSortedAndComplete(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("registry must not be empty")
	}
	ids := make([]string, len(all))
	for i, c := range all {
		ids[i] = c.ID
		if c.ID == "" || c.Title == "" || c.Kind == "" || c.Description == "" {
			t.Errorf("check %q has an empty required field: %+v", c.ID, c)
		}
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("All() must be sorted by ID, got %v", ids)
	}
	// IDs() must agree with All().
	if got := IDs(); len(got) != len(all) {
		t.Errorf("IDs() len %d != All() len %d", len(got), len(all))
	}
}

// TestCheckIDFormat keeps check IDs to the lower_snake_case convention the
// MCP tool names and CLI subcommands use, so a control author can rely on
// one spelling everywhere.
func TestCheckIDFormat(t *testing.T) {
	re := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	for _, c := range All() {
		if !re.MatchString(c.ID) {
			t.Errorf("check ID %q is not lower_snake_case", c.ID)
		}
	}
}
