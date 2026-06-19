// Package compliance defines the canonical on-disk shape of the
// compliance/<framework>_mapping.yaml files.
//
// These types are the single source of truth shared by the library's
// map_compliance_control tool (internal/tools) and the `skills-check
// evidence` command (cmd/skills-check). Before this package existed the
// control/mapping shape was declared twice — once in each consumer — and
// the two definitions drifted (only one carried explicit yaml tags). Keep
// the shape here and alias it from the consumers so it can never diverge
// again.
//
// Schema versions:
//
//	1.0 — controls map to prevention Skills only (advisory coverage).
//	2.0 — controls additionally map to automated Checks (a runnable
//	      detection from internal/checks) and CWE identifiers, so coverage
//	      can be backed by verification, not just intent. v2 is a superset:
//	      a 1.0 file parses unchanged (Checks/CWE simply stay empty).
package compliance

// Control is one row under a framework mapping's `controls:` list.
type Control struct {
	ID          string `json:"id"          yaml:"id"`
	Title       string `json:"title"       yaml:"title"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`

	// Skills are the prevention skill IDs that advise on this control
	// (schema 1.0+). Advisory: presence in the library is "intent".
	Skills []string `json:"skills,omitempty" yaml:"skills,omitempty"`

	// Checks are the automated detection IDs (see internal/checks) that
	// VERIFY this control (schema 2.0+). A control backed by checks can be
	// proven pass/fail against real code, not merely advised.
	Checks []string `json:"checks,omitempty" yaml:"checks,omitempty"`

	// CWE lists the Common Weakness Enumeration IDs this control guards
	// against (schema 2.0+), e.g. "CWE-79". The cross-framework spine that
	// joins control ↔ CWE ↔ skill ↔ check.
	CWE []string `json:"cwe,omitempty" yaml:"cwe,omitempty"`

	References []string `json:"references,omitempty" yaml:"references,omitempty"`
}

// Mapping is one framework's compliance YAML on disk.
type Mapping struct {
	SchemaVersion string    `json:"schema_version" yaml:"schema_version"`
	Framework     string    `json:"framework"      yaml:"framework"`
	Version       string    `json:"version"        yaml:"version"`
	LastUpdated   string    `json:"last_updated"   yaml:"last_updated"`
	Controls      []Control `json:"controls"       yaml:"controls"`
}
