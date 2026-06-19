package checks

import (
	"reflect"
	"testing"
)

func TestVerdict(t *testing.T) {
	cases := []struct {
		name string
		in   []Result
		want string
	}{
		{"none", nil, ""},
		{"all pass", []Result{{Status: StatusPass}, {Status: StatusPass}}, VerdictVerified},
		{"a finding outranks pass", []Result{{Status: StatusPass}, {Status: StatusFail}}, VerdictFindings},
		{"error when no finding", []Result{{Status: StatusPass}, {Status: StatusError}}, VerdictError},
		{"finding outranks error", []Result{{Status: StatusError}, {Status: StatusFail}}, VerdictFindings},
		{"only lookups", []Result{{Status: StatusNotRun}, {Status: StatusNotRun}}, VerdictNotVerifiable},
	}
	for _, tc := range cases {
		if got := Verdict(tc.in); got != tc.want {
			t.Errorf("%s: Verdict = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func TestByCWE(t *testing.T) {
	// scan_secrets and check_secret_pattern are both tagged CWE-798 in the
	// registry; nothing is tagged with a fabricated CWE.
	got := ByCWE("CWE-798")
	if !reflect.DeepEqual(got, []string{"check_secret_pattern", "scan_secrets"}) {
		t.Errorf("ByCWE(CWE-798) = %v, want [check_secret_pattern scan_secrets]", got)
	}
	if len(ByCWE("CWE-0000000")) != 0 {
		t.Error("ByCWE of an unmapped CWE must be empty")
	}
	// Every ID returned must be a real registered check.
	for _, id := range ByCWE("CWE-1104") {
		if !IsKnown(id) {
			t.Errorf("ByCWE returned unknown check %q", id)
		}
	}
}
