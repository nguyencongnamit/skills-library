package tools

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeSBOMFixture drops a small multi-ecosystem project into a fresh
// temp dir: one npm lockfile, one go.sum, and a second npm lockfile in a
// subdirectory that re-declares the same package. The duplicate exercises
// de-duplication; the subdirectory exercises recursive discovery.
func writeSBOMFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"package-lock.json":         `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`,
		"go.sum":                    "github.com/stretchr/testify v1.8.4 h1:abc=\n",
		"service/package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.3.0"}}}`,
	}
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func componentByName(bom *SBOM, name string) *SBOMComponent {
	for i := range bom.Components {
		if bom.Components[i].Name == name {
			return &bom.Components[i]
		}
	}
	return nil
}

func TestGenerateSBOMShape(t *testing.T) {
	lib := newLibrary(t)
	bom, err := lib.GenerateSBOM(writeSBOMFixture(t))
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	if bom.BOMFormat != "CycloneDX" || bom.SpecVersion != "1.5" || bom.Version != 1 {
		t.Errorf("envelope = %q/%q/%d, want CycloneDX/1.5/1",
			bom.BOMFormat, bom.SpecVersion, bom.Version)
	}
	if bom.Metadata.Component == nil || bom.Metadata.Component.Type != "application" {
		t.Fatalf("metadata.component should be the application subject, got %+v", bom.Metadata.Component)
	}
	if len(bom.Metadata.Tools) == 0 || bom.Metadata.Tools[0].Name != "skills-check" {
		t.Errorf("metadata.tools should credit skills-check, got %+v", bom.Metadata.Tools)
	}
}

func TestGenerateSBOMDeduplicates(t *testing.T) {
	lib := newLibrary(t)
	bom, err := lib.GenerateSBOM(writeSBOMFixture(t))
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	// left-pad@1.3.0 appears in two lockfiles -> exactly one component.
	n := 0
	for _, c := range bom.Components {
		if c.Name == "left-pad" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("left-pad should de-duplicate to 1 component, got %d", n)
	}
	// Both ecosystems are represented (npm + go discovered recursively).
	if componentByName(bom, "left-pad") == nil {
		t.Error("missing npm component left-pad")
	}
	if componentByName(bom, "github.com/stretchr/testify") == nil {
		t.Error("missing go component testify")
	}
}

func TestGenerateSBOMPackageURLs(t *testing.T) {
	lib := newLibrary(t)
	bom, err := lib.GenerateSBOM(writeSBOMFixture(t))
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	lp := componentByName(bom, "left-pad")
	if lp == nil {
		t.Fatal("missing left-pad")
	}
	if want := "pkg:npm/left-pad@1.3.0"; lp.PURL != want {
		t.Errorf("left-pad purl = %q, want %q", lp.PURL, want)
	}
	if lp.BOMRef != lp.PURL {
		t.Errorf("bom-ref %q should equal purl %q", lp.BOMRef, lp.PURL)
	}
	if lp.Type != "library" {
		t.Errorf("dependency component type = %q, want library", lp.Type)
	}
	if tf := componentByName(bom, "github.com/stretchr/testify"); tf != nil {
		if want := "pkg:golang/github.com/stretchr/testify@v1.8.4"; tf.PURL != want {
			t.Errorf("testify purl = %q, want %q", tf.PURL, want)
		}
	}
}

func TestGenerateSBOMDeterministic(t *testing.T) {
	lib := newLibrary(t)
	dir := writeSBOMFixture(t)
	a, err := lib.GenerateSBOM(dir)
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	b, err := lib.GenerateSBOM(dir)
	if err != nil {
		t.Fatalf("GenerateSBOM: %v", err)
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if string(ja) != string(jb) {
		t.Errorf("SBOM generation is not deterministic:\n%s\n---\n%s", ja, jb)
	}
}

func TestGenerateSBOMEmptyProject(t *testing.T) {
	lib := newLibrary(t)
	bom, err := lib.GenerateSBOM(t.TempDir())
	if err != nil {
		t.Fatalf("GenerateSBOM on empty dir should not error: %v", err)
	}
	if len(bom.Components) != 0 {
		t.Errorf("empty project should yield 0 components, got %d", len(bom.Components))
	}
	if bom.Components == nil {
		t.Error("Components should be non-nil ([]) even when empty, for stable JSON")
	}
}
