package tools

// deep_scan.go composes the dependency-side detection legs — scan_dependencies,
// DQ-V.1 import reachability, and DQ-V.2 CVE code-pattern reachability — into
// ONE reachability-prioritized triage list. It answers the question none of the
// individual tools answers alone: "of everything flagged in this project, what
// should I look at first?"
//
// Priority is REACHABILITY, not raw severity: a flagged package you actually
// import (P1) outranks one that only sits in a lockfile (P2), because the latter
// is usually a transitive dependency you may never reach. A CVE code-pattern
// match is P1 — the vulnerable pattern is literally in your source. Within a
// tier, findings sort by severity. Like the legs it composes, this is ADVISORY
// and never gate-wired.

import "sort"

// DeepFinding is one triaged risk: a dependency finding (with its import-
// reachability verdict) or a CVE code-pattern match, tagged with a reachability
// Priority and a one-line rationale.
type DeepFinding struct {
	Priority  int    `json:"priority"` // 1 = reachable, 2 = present-only
	Kind      string `json:"kind"`     // "dependency" | "cve-pattern"
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Why       string `json:"why"`
	Package   string `json:"package,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Version   string `json:"version,omitempty"`
	CVE       string `json:"cve,omitempty"`
	Imported  bool   `json:"imported,omitempty"`
	File      string `json:"file,omitempty"`
	Line      int    `json:"line,omitempty"`
}

// DeepScanReport is what scan-deep / deep_scan return.
type DeepScanReport struct {
	ScanPath string        `json:"scan_path"`
	Findings []DeepFinding `json:"findings"`
	P1Count  int           `json:"p1_reachable_count"`
	P2Count  int           `json:"p2_present_count"`
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
		case !f.Analyzed:
			df.Priority = 2
			df.Why = "flagged package present; reachability not analyzable for this ecosystem"
		default:
			df.Priority = 2
			df.Why = "flagged package present but not directly imported (likely transitive — verify)"
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
		if f.Priority == 1 {
			report.P1Count++
		} else {
			report.P2Count++
		}
	}
	return report, nil
}
