package tools

import (
	"os/exec"
	"sort"
)

// EngineStatus is one row of the scan_<scanner>_engines tool response.
// It mirrors the marker payload but adds runtime fields (Available,
// ResolvedPath) the MCP server computes by probing the host at call
// time. The downstream agent uses this to render a multi-select menu.
type EngineStatus struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Scanner      string `json:"scanner"`
	Description  string `json:"description,omitempty"`
	Available    bool   `json:"available"`
	ResolvedPath string `json:"resolved_path,omitempty"`
	OutputFormat string `json:"output_format,omitempty"`
	InstallHint  string `json:"install_hint,omitempty"`
	Upstream     string `json:"upstream,omitempty"`
	SkillID      string `json:"declared_in_skill,omitempty"`

	// Detect / Execute are intentionally NOT exposed in the discovery
	// response. They are implementation detail the dispatcher uses;
	// surfacing them in the menu would create a security surface
	// (caller could read the argv template, mutate it, and replay).
	// If a future feature needs them — e.g. "show me what the engine
	// is going to run" — add a separate diagnostics endpoint.
	Detect  []string `json:"-"`
	Execute []string `json:"-"`
}

// ListEnginesResult is what the scan_<scanner>_engines MCP tool
// returns. The Scanner field echoes the input so a caller reading the
// response without remembering its own query can still tell what it
// got.
type ListEnginesResult struct {
	Scanner string         `json:"scanner"`
	Engines []EngineStatus `json:"engines"`
}

// ListEngines is the handler behind scan_<scanner>_engines MCP tools.
// It harvests the engine registry (built from SKILL.md markers) for
// the requested scanner type and decorates each entry with per-host
// availability (binary on PATH? what version?).
//
// Always succeeds — an unknown scanner type returns an empty Engines
// slice rather than an error, so a caller can blindly call
// scan_dockerfile_engines / scan_secrets_engines / etc. without
// branching on the scanner name.
//
// The result is sorted: builtin engines first (always available),
// then external engines alphabetically. This gives the menu a
// predictable shape — the user always sees the offline fallback at
// the top of the list.
func (l *Library) ListEngines(scanner string) (*ListEnginesResult, error) {
	markers, err := l.EnginesForScanner(scanner)
	if err != nil {
		return nil, err
	}
	out := make([]EngineStatus, 0, len(markers))
	for _, m := range markers {
		status := EngineStatus{
			Name:         m.Name,
			Type:         m.Type,
			Scanner:      m.Scanner,
			Description:  m.Description,
			OutputFormat: m.OutputFormat,
			InstallHint:  m.InstallHint,
			Upstream:     m.Upstream,
			SkillID:      m.SkillID,
		}
		switch m.Type {
		case "builtin":
			// The in-process scanner is always available because the
			// secure-code binary itself implements it.
			status.Available = true
		case "external":
			path, err := exec.LookPath(m.Binary)
			if err == nil {
				status.Available = true
				status.ResolvedPath = path
			}
		}
		out = append(out, status)
	}
	sort.SliceStable(out, func(i, j int) bool {
		// builtin before external; same-type alphabetical
		if (out[i].Type == "builtin") != (out[j].Type == "builtin") {
			return out[i].Type == "builtin"
		}
		return out[i].Name < out[j].Name
	})
	return &ListEnginesResult{Scanner: scanner, Engines: out}, nil
}
