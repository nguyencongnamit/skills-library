package tools

import (
	"strings"
	"testing"
)

func TestExtractEngineMarkersHappyPath(t *testing.T) {
	body := []byte(`# Some skill

Random prose, no markers here.

- A bullet with no marker — should be ignored.

- An external engine.
  <!-- engine: {
    name: hadolint,
    type: external,
    scanner: dockerfile,
    binary: hadolint,
    execute: [hadolint, --format, sarif, "{file_path}"],
    output_format: sarif,
    install_hint: "brew install hadolint"
  } -->

- A builtin engine.
  <!-- engine: {
    name: internal,
    type: builtin,
    scanner: dockerfile,
    output_format: dockerfile_finding
  } -->
`)
	got, err := extractEngineMarkers("test-skill", body)
	if err != nil {
		t.Fatalf("extractEngineMarkers: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d markers, want 2", len(got))
	}
	if got[0].Name != "hadolint" || got[0].Type != "external" {
		t.Errorf("first marker = %+v", got[0])
	}
	if got[0].SkillID != "test-skill" {
		t.Errorf("first marker SkillID = %q, want %q", got[0].SkillID, "test-skill")
	}
	if got[1].Name != "internal" || got[1].Type != "builtin" {
		t.Errorf("second marker = %+v", got[1])
	}
	// Builtin engine omits Binary / Execute — that's valid.
	if got[1].Binary != "" || len(got[1].Execute) > 0 {
		t.Errorf("builtin should not need binary/execute, got %+v", got[1])
	}
}

func TestExtractEngineMarkersValidatesRequiredFields(t *testing.T) {
	cases := []struct {
		name      string
		body      string
		wantError string
	}{
		{
			"missing name",
			`<!-- engine: { type: external, scanner: dockerfile, binary: foo } -->`,
			"'name'",
		},
		{
			"missing type",
			`<!-- engine: { name: foo, scanner: dockerfile, binary: foo } -->`,
			"'type'",
		},
		{
			"invalid type",
			`<!-- engine: { name: foo, type: pluginX, scanner: dockerfile, binary: foo } -->`,
			`invalid type "pluginX"`,
		},
		{
			"missing scanner",
			`<!-- engine: { name: foo, type: external, binary: foo } -->`,
			"'scanner'",
		},
		{
			"invalid scanner",
			`<!-- engine: { name: foo, type: external, scanner: nonsense, binary: foo } -->`,
			`invalid scanner "nonsense"`,
		},
		{
			"external without binary",
			`<!-- engine: { name: foo, type: external, scanner: dockerfile } -->`,
			"declare 'binary'",
		},
		{
			"invalid output_format",
			`<!-- engine: { name: foo, type: external, scanner: dockerfile, binary: foo, output_format: weird } -->`,
			`invalid output_format "weird"`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := extractEngineMarkers("test", []byte(c.body))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", c.wantError)
			}
			if !strings.Contains(err.Error(), c.wantError) {
				t.Errorf("error %q does not contain %q", err.Error(), c.wantError)
			}
		})
	}
}

func TestExtractEngineMarkersRejectsDuplicates(t *testing.T) {
	// Two markers with the same (scanner, name) within the same skill
	// is an authoring mistake — fail loudly so the SKILL.md author
	// catches it before the registry ends up with a duplicate.
	body := []byte(`
<!-- engine: { name: foo, type: external, scanner: dockerfile, binary: foo } -->

<!-- engine: { name: foo, type: external, scanner: dockerfile, binary: foo } -->
`)
	_, err := extractEngineMarkers("test", body)
	if err == nil {
		t.Fatal("expected duplicate error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("error does not mention duplicate: %v", err)
	}
}

func TestExtractEngineMarkersAllowsBuiltinWithoutBinary(t *testing.T) {
	// type=builtin engines have no binary because they're served from
	// the in-process scanner. The validator must NOT require a binary
	// for them.
	body := []byte(`<!-- engine: { name: internal, type: builtin, scanner: dockerfile } -->`)
	got, err := extractEngineMarkers("test", body)
	if err != nil {
		t.Fatalf("extractEngineMarkers: %v", err)
	}
	if len(got) != 1 || got[0].Name != "internal" {
		t.Fatalf("got %+v, want one internal engine", got)
	}
}

func TestExtractEngineMarkersMultilineMarker(t *testing.T) {
	// The regex must handle markers that span multiple lines — engine
	// declarations get long enough that authors want to break them up.
	body := []byte(`<!-- engine: {
  name: hadolint,
  type: external,
  scanner: dockerfile,
  binary: hadolint,
  execute: [
    hadolint,
    --format,
    sarif,
    "{file_path}"
  ],
  output_format: sarif,
  install_hint: "brew install hadolint",
  upstream: "https://github.com/hadolint/hadolint"
} -->`)
	got, err := extractEngineMarkers("test", body)
	if err != nil {
		t.Fatalf("extractEngineMarkers: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d markers, want 1", len(got))
	}
	want := []string{"hadolint", "--format", "sarif", "{file_path}"}
	if len(got[0].Execute) != len(want) {
		t.Fatalf("execute = %v, want %v", got[0].Execute, want)
	}
	for i, v := range want {
		if got[0].Execute[i] != v {
			t.Errorf("execute[%d] = %q, want %q", i, got[0].Execute[i], v)
		}
	}
}

func TestListEnginesReturnsInternalForDockerfile(t *testing.T) {
	// Integration check against the real repo's
	// container-security/SKILL.md, which has the internal engine
	// declared in the new `## Scanner engines` section.
	lib, err := NewLibrary(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	res, err := lib.ListEngines("dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	if res.Scanner != "dockerfile" {
		t.Errorf("Scanner = %q, want dockerfile", res.Scanner)
	}
	if len(res.Engines) == 0 {
		t.Fatal("no engines returned; expected at least the internal engine")
	}
	var seenInternal bool
	for _, e := range res.Engines {
		if e.Name == "internal" {
			seenInternal = true
			if e.Type != "builtin" {
				t.Errorf("internal engine Type = %q, want builtin", e.Type)
			}
			if !e.Available {
				t.Errorf("internal engine must report Available=true")
			}
			if e.SkillID != "container-security" {
				t.Errorf("internal engine SkillID = %q, want container-security", e.SkillID)
			}
		}
	}
	if !seenInternal {
		t.Errorf("internal engine missing from %+v", res.Engines)
	}
}

func TestListEnginesReturnsEnginesForSecrets(t *testing.T) {
	// Integration check against secret-detection/SKILL.md, which
	// declares the internal builtin and the gitleaks external engine.
	lib, err := NewLibrary(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	res, err := lib.ListEngines("secrets")
	if err != nil {
		t.Fatal(err)
	}
	var seenInternal, seenGitleaks bool
	for _, e := range res.Engines {
		switch e.Name {
		case "internal":
			seenInternal = true
			if e.Type != "builtin" || !e.Available {
				t.Errorf("internal secrets engine = %+v; want builtin/available", e)
			}
			if e.SkillID != "secret-detection" {
				t.Errorf("internal secrets engine SkillID = %q, want secret-detection", e.SkillID)
			}
		case "gitleaks":
			seenGitleaks = true
			if e.Type != "external" {
				t.Errorf("gitleaks Type = %q, want external", e.Type)
			}
		}
	}
	if !seenInternal || !seenGitleaks {
		t.Errorf("expected internal+gitleaks secrets engines, got %+v", res.Engines)
	}
	// builtin must sort before external.
	if len(res.Engines) >= 2 && res.Engines[0].Type != "builtin" {
		t.Errorf("first engine should be builtin, got %q", res.Engines[0].Type)
	}
}

func TestListEnginesUnknownScannerReturnsEmpty(t *testing.T) {
	// Calling scan_<unknown>_engines should not error — it should
	// just return zero engines so the agent gets a deterministic
	// "nothing registered" response.
	lib, err := NewLibrary(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	res, err := lib.ListEngines("made-up-scanner-type")
	if err != nil {
		t.Fatalf("ListEngines: %v", err)
	}
	if len(res.Engines) != 0 {
		t.Errorf("unknown scanner returned %d engines; want 0", len(res.Engines))
	}
}

func TestListEnginesBuiltinSortedFirst(t *testing.T) {
	// builtin engines should sort before external ones so the menu
	// always shows the offline fallback first.
	lib, err := NewLibrary(repoRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	res, err := lib.ListEngines("dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	// If only builtin is registered, this test passes trivially. The
	// real assertion fires when external engines are added in PR-B.
	sawExternal := false
	for _, e := range res.Engines {
		if e.Type == "external" {
			sawExternal = true
		}
		if e.Type == "builtin" && sawExternal {
			t.Errorf("builtin %q appeared after an external engine — sort order wrong: %+v", e.Name, res.Engines)
		}
	}
}
