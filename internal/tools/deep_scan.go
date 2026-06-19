package tools

// deep_scan.go composes the dependency-side detection legs — scan_dependencies,
// DQ-V.1 import reachability, and DQ-V.2 CVE code-pattern reachability — into
// ONE reachability-prioritized triage list. It answers the question none of the
// individual tools answers alone: "of everything flagged in this project, what
// should I look at first?"
//
// Priority is REACHABILITY, not raw severity:
//   P1 — a flagged package you directly import, or a CVE code-pattern match
//        literally in your source: the risk is in code you reach.
//   P2 — a flagged package reachable transitively (npm: pulled in by a package
//        you import, carried with the dependency path) OR one present in an
//        ecosystem whose reachability cannot be analyzed.
//   P3 — a flagged package the npm dependency graph shows no import path to
//        (likely unused or dev-only).
// A CVE code-pattern match is always P1. Within a tier, findings sort by
// severity. Like the legs it composes, this is ADVISORY and never gate-wired.

import (
	"sort"
	"strings"
)

// DeepFinding is one triaged risk: a dependency finding (with its import-
// reachability verdict) or a CVE code-pattern match, tagged with a reachability
// Priority and a one-line rationale.
type DeepFinding struct {
	Priority  int      `json:"priority"` // 1 reachable · 2 transitive/unknown · 3 unreachable
	Kind      string   `json:"kind"`     // "dependency" | "cve-pattern"
	Severity  string   `json:"severity"`
	Title     string   `json:"title"`
	Why       string   `json:"why"`
	Package   string   `json:"package,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Version   string   `json:"version,omitempty"`
	CVE       string   `json:"cve,omitempty"`
	Imported  bool     `json:"imported,omitempty"`
	Via       []string `json:"via,omitempty"` // transitive path: imported-root → … → package
	File      string   `json:"file,omitempty"`
	Line      int      `json:"line,omitempty"`
}

// DeepScanReport is what scan-deep / deep_scan return.
type DeepScanReport struct {
	ScanPath string        `json:"scan_path"`
	Findings []DeepFinding `json:"findings"`
	P1Count  int           `json:"p1_reachable_count"`
	P2Count  int           `json:"p2_present_count"`
	P3Count  int           `json:"p3_unreachable_count"`
}

// DeepScan runs the dependency reachability analysis and the CVE code-pattern
// scan over scanPath, then merges them into one reachability-prioritized list.
func (l *Library) DeepScan(scanPath string) (*DeepScanReport, error) {
	reach, err := l.AnalyzeReachability(scanPath)
	if err != nil {
		return nil, err
	}
	cvePat, err := l.ScanCVEPatterns(scanPath)
	if err != nil {
		return nil, err
	}

	report := &DeepScanReport{ScanPath: scanPath, Findings: []DeepFinding{}}

	for _, f := range reach.Findings {
		df := DeepFinding{
			Kind:      "dependency",
			Severity:  f.Severity,
			Title:     f.Package + " (" + f.Category + ")",
			Package:   f.Package,
			Ecosystem: f.Ecosystem,
			Version:   f.Version,
			Imported:  f.Imported,
		}
		switch {
		case f.Imported:
			df.Priority = 1
			df.Why = "flagged package is directly imported in source"
			if len(f.Sites) > 0 {
				df.File, df.Line = f.Sites[0].File, f.Sites[0].Line
			}
		case len(f.TransitiveVia) > 0:
			df.Priority = 2
			df.Via = f.TransitiveVia
			df.Why = "reachable via " + strings.Join(f.TransitiveVia, " → ") + " (transitive dependency of code you import)"
		case f.TransitiveAnalyzed:
			df.Priority = 3
			df.Why = "in a lockfile but no import path from your code (dependency graph: unreachable — likely unused or dev-only)"
		case !f.Analyzed:
			df.Priority = 2
			df.Why = "present; reachability not analyzable for this ecosystem"
		default:
			df.Priority = 2
			df.Why = "present, not directly imported (transitive reachability not analyzed for this ecosystem)"
		}
		report.Findings = append(report.Findings, df)
	}

	for _, f := range cvePat.Findings {
		report.Findings = append(report.Findings, DeepFinding{
			Priority: 1,
			Kind:     "cve-pattern",
			Severity: f.Severity,
			Title:    f.CVE + " (" + f.Name + ")",
			CVE:      f.CVE,
			File:     f.File,
			Line:     f.Line,
			Why:      "vulnerable code pattern present in source",
		})
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		if ra, rb := severityRank(a.Severity), severityRank(b.Severity); ra != rb {
			return ra > rb
		}
		if a.Title != b.Title {
			return a.Title < b.Title
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
	for _, f := range report.Findings {
		switch f.Priority {
		case 1:
			report.P1Count++
		case 3:
			report.P3Count++
		default:
			report.P2Count++
		}
	}
	return report, nil
}
