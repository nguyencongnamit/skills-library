package tools

import (
	"encoding/json"
	"fmt"
	"strings"
)

// EngineFinding is one normalized finding produced by an external
// scanner engine (e.g. hadolint) after its native output has been
// parsed. It is intentionally a small, engine-agnostic shape so the
// MCP response for an external-engine scan looks the same regardless
// of which tool produced it.
type EngineFinding struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
	Engine   string `json:"engine"`
}

// sarifLevelToSeverity maps a SARIF result `level` (error / warning /
// note / none) to secure-code's severity vocabulary so external-engine
// findings sort alongside the built-in ones. SARIF's default level is
// "warning" when omitted (per the 2.1.0 spec), which we surface as
// "medium".
func sarifLevelToSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "error":
		return "high"
	case "warning", "":
		return "medium"
	case "note":
		return "low"
	case "none":
		return "info"
	default:
		return "medium"
	}
}

// sarifDocument is the minimal subset of the SARIF 2.1.0 schema that
// parseSARIF needs to lift findings out of a tool's output. Fields not
// listed here are ignored, so a fuller SARIF document still parses.
type sarifDocument struct {
	Runs []struct {
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// parseSARIF decodes a SARIF 2.1.0 document (e.g. `hadolint --format
// sarif`) into normalized EngineFinding rows tagged with the engine
// name. It is deliberately lenient: a result with no location yields a
// finding with Line==0 rather than an error, and an empty `runs` array
// returns an empty slice (not nil) so the JSON response is a stable
// `[]`.
func parseSARIF(data []byte, engine string) ([]EngineFinding, error) {
	var doc sarifDocument
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse SARIF from engine %q: %w", engine, err)
	}
	out := []EngineFinding{}
	for _, run := range doc.Runs {
		for _, r := range run.Results {
			line := 0
			if len(r.Locations) > 0 {
				line = r.Locations[0].PhysicalLocation.Region.StartLine
			}
			out = append(out, EngineFinding{
				RuleID:   r.RuleID,
				Severity: sarifLevelToSeverity(r.Level),
				Message:  strings.TrimSpace(r.Message.Text),
				Line:     line,
				Engine:   engine,
			})
		}
	}
	return out, nil
}
