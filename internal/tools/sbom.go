package tools

// sbom.go generates a CycloneDX 1.5 software bill of materials (DQ-H.4) from a
// project's dependency lockfiles. It reuses the same lockfile discovery and
// parsing as scan_dependencies, so the SBOM inventory is exactly the set of
// (name, version, ecosystem) tuples the scanner evaluates — one resolution
// path, no second list to drift.
//
// The output is the standard CycloneDX JSON shape, so it drops straight into
// the SBOM-consuming tools an auditor already uses (and satisfies the EU CRA
// AnnexI.2.1 "draw up a software bill of materials" obligation with a real
// artifact, not just an intent). Generation is pure and deterministic — no
// network, no timestamp — so the same tree always yields byte-identical bytes,
// which keeps it diffable in CI.

import (
	"path/filepath"
	"sort"
	"strings"

	"github.com/namncqualgo/skills-library/internal/tools/parsers"
)

// SBOM is a CycloneDX 1.5 bill of materials.
type SBOM struct {
	BOMFormat   string          `json:"bomFormat"`   // always "CycloneDX"
	SpecVersion string          `json:"specVersion"` // "1.5"
	Version     int             `json:"version"`     // BOM revision, 1
	Metadata    SBOMMetadata    `json:"metadata"`
	Components  []SBOMComponent `json:"components"`
}

// SBOMMetadata describes the BOM's subject and the tool that produced it.
type SBOMMetadata struct {
	Tools     []SBOMTool     `json:"tools,omitempty"`
	Component *SBOMComponent `json:"component,omitempty"`
}

// SBOMTool identifies the generator.
type SBOMTool struct {
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// SBOMComponent is one inventoried package (or the subject application).
type SBOMComponent struct {
	Type      string `json:"type"` // "library" for deps, "application" for the subject
	Name      string `json:"name"`
	Version   string `json:"version,omitempty"`
	PURL      string `json:"purl,omitempty"`
	BOMRef    string `json:"bom-ref,omitempty"`
	Ecosystem string `json:"-"` // internal: used for stable sort, not serialised
}

// GenerateSBOM discovers every recognised lockfile under scanPath, parses each
// into its resolved (name, version, ecosystem) tuples, de-duplicates, and
// returns a CycloneDX 1.5 BOM. Unparseable lockfiles are skipped (mirroring
// the scanner's per-file tolerance) so one bad manifest never aborts the BOM.
func (l *Library) GenerateSBOM(scanPath string) (*SBOM, error) {
	lockfiles, err := DiscoverLockfiles(scanPath)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	comps := []SBOMComponent{}
	for _, lf := range lockfiles {
		body, _, err := l.readScanFile("generate_sbom", lf)
		if err != nil {
			continue
		}
		deps, err := parsers.Parse(lf, body)
		if err != nil {
			continue
		}
		for _, d := range deps {
			if d.Name == "" {
				continue
			}
			key := d.Ecosystem + "|" + d.Name + "|" + d.Version
			if seen[key] {
				continue
			}
			seen[key] = true
			purl := purlFor(d)
			comps = append(comps, SBOMComponent{
				Type:      "library",
				Name:      d.Name,
				Version:   d.Version,
				PURL:      purl,
				BOMRef:    purl,
				Ecosystem: d.Ecosystem,
			})
		}
	}
	// Stable order: by purl (which encodes ecosystem+name+version), falling
	// back to name then version for components without a purl. Deterministic
	// output keeps the BOM diffable across runs.
	sort.Slice(comps, func(i, j int) bool {
		if comps[i].PURL != comps[j].PURL {
			return comps[i].PURL < comps[j].PURL
		}
		if comps[i].Name != comps[j].Name {
			return comps[i].Name < comps[j].Name
		}
		return comps[i].Version < comps[j].Version
	})

	subject := filepath.Base(filepath.Clean(scanPath))
	if subject == "." || subject == string(filepath.Separator) {
		subject = "project"
	}
	return &SBOM{
		BOMFormat:   "CycloneDX",
		SpecVersion: "1.5",
		Version:     1,
		Metadata: SBOMMetadata{
			Tools:     []SBOMTool{{Vendor: "skills-library", Name: "skills-check"}},
			Component: &SBOMComponent{Type: "application", Name: subject},
		},
		Components: comps,
	}, nil
}

// purlEcosystem maps the parser's ecosystem label to the Package URL "type"
// component (https://github.com/package-url/purl-spec). Returns "" for an
// ecosystem with no defined purl type, in which case purlFor yields "".
func purlEcosystem(ecosystem string) string {
	switch strings.ToLower(ecosystem) {
	case "npm":
		return "npm"
	case "pypi":
		return "pypi"
	case "go", "golang":
		return "golang"
	case "crates", "cargo":
		return "cargo"
	case "maven":
		return "maven"
	case "nuget":
		return "nuget"
	case "rubygems", "gem":
		return "gem"
	}
	return ""
}

// purlFor builds a Package URL for a resolved dependency, or "" when the
// ecosystem has no purl type. Maven coordinates ("group:artifact") map to a
// purl namespace/name; every other ecosystem uses the bare name.
func purlFor(d parsers.Dependency) string {
	typ := purlEcosystem(d.Ecosystem)
	if typ == "" {
		return ""
	}
	namespace, name := "", d.Name
	if typ == "maven" {
		if i := strings.LastIndex(name, ":"); i > 0 {
			namespace, name = name[:i], name[i+1:]
		}
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteString("/")
	if namespace != "" {
		b.WriteString(namespace)
		b.WriteString("/")
	}
	b.WriteString(name)
	if d.Version != "" {
		b.WriteString("@")
		b.WriteString(d.Version)
	}
	return b.String()
}
