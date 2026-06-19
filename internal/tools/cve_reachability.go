package tools

// cve_reachability.go implements DQ-V.2: language-scoped CVE code-pattern
// reachability. Where DQ-V.1 asks "is this flagged package imported?", this
// asks the source-level question "does the *vulnerable code pattern* of a
// known CVE actually appear in first-party source?".
//
// It is DB-guided depth, not generic SAST: the only patterns it runs are the
// curated `code_patterns` regexes already shipped in the verified CVE DB
// (vulnerabilities/cve/code-relevant/cve_patterns.json), and each is applied
// only to files whose language the CVE entry declares. The regexes are
// hand-tuned to be specific (e.g. Log4Shell's `${jndi:...}`), which is the
// FP control.
//
// HONESTY: this is ADVISORY. A match means "a code pattern associated with
// CVE-X is present here — verify"; it is not proof of exploitability (no
// dataflow or version correlation), and matches inside comments are not
// stripped. It is deliberately NOT wired into the build-failing `gate`, so a
// curated-but-broad regex can never break a user's CI.

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const cvePatternMatchMaxLen = 160

// cveSourceExtensions maps a source-file extension to the cve_patterns.json
// language label. A file whose extension is absent is not scanned. The
// "appliance" language (Citrix/F5/etc.) has no source extension by design.
var cveSourceExtensions = map[string]string{
	".java":   "java",
	".kt":     "kotlin",
	".kts":    "kotlin",
	".scala":  "scala",
	".groovy": "groovy",
	".py":     "python",
	".pyi":    "python",
	".c":      "c",
	".h":      "c",
	".cc":     "c++",
	".cpp":    "c++",
	".cxx":    "c++",
	".hpp":    "c++",
	".hh":     "c++",
	".go":     "go",
	".cs":     "csharp",
	".js":     "javascript",
	".jsx":    "javascript",
	".mjs":    "javascript",
	".cjs":    "javascript",
	".ts":     "typescript",
	".tsx":    "typescript",
	".php":    "php",
	".rb":     "ruby",
	".sh":     "shell",
	".bash":   "shell",
	".pl":     "perl",
	".pm":     "perl",
	".yml":    "yaml",
	".yaml":   "yaml",
	".sql":    "sql",
}

// CVEPatternFinding is one source location whose text matched a CVE's curated
// code pattern.
type CVEPatternFinding struct {
	CVE        string `json:"cve"`
	Name       string `json:"name"`
	Severity   string `json:"severity"`
	AttackType string `json:"attack_type,omitempty"`
	Language   string `json:"language"`
	File       string `json:"file"`
	Line       int    `json:"line"`
	Pattern    string `json:"pattern"`
	Match      string `json:"match"`
}

// CVEReachabilityReport is what scan-cve-patterns / scan_cve_patterns return.
// PatternsSkipped counts curated regexes that do not compile under Go's RE2
// engine (PCRE lookaround/backreferences) — surfaced so the coverage gap is
// visible rather than silent.
type CVEReachabilityReport struct {
	ScanPath        string              `json:"scan_path"`
	Findings        []CVEPatternFinding `json:"findings"`
	FilesScanned    int                 `json:"files_scanned"`
	PatternsActive  int                 `json:"patterns_active"`
	PatternsSkipped int                 `json:"patterns_skipped"`
}

// compiledCVEPattern is one code_patterns regex paired with its CVE metadata.
type compiledCVEPattern struct {
	re   *regexp.Regexp
	raw  string
	meta struct{ id, name, severity, attackType string }
}

// ScanCVEPatterns walks first-party source under scanPath and, for each file,
// applies the curated code_patterns of every CVE that declares the file's
// language, reporting each match. Patterns that do not compile under RE2 are
// skipped and counted (never fatal).
func (l *Library) ScanCVEPatterns(scanPath string) (*CVEReachabilityReport, error) {
	cve, err := l.loadCVEPatterns()
	if err != nil {
		return nil, err
	}
	report := &CVEReachabilityReport{ScanPath: scanPath, Findings: []CVEPatternFinding{}}

	// Compile patterns once, indexed by language.
	byLang := map[string][]compiledCVEPattern{}
	for _, e := range cve.Entries {
		for _, raw := range e.CodePatterns {
			re, cerr := regexp.Compile(raw)
			if cerr != nil {
				report.PatternsSkipped++
				continue
			}
			report.PatternsActive++
			cp := compiledCVEPattern{re: re, raw: raw}
			cp.meta.id, cp.meta.name, cp.meta.severity, cp.meta.attackType = e.CVE, e.Name, e.Severity, e.AttackType
			for _, lang := range e.Languages {
				byLang[strings.ToLower(strings.TrimSpace(lang))] = append(byLang[strings.ToLower(strings.TrimSpace(lang))], cp)
			}
		}
	}
	if report.PatternsActive == 0 {
		return report, nil
	}

	files, err := WalkScanFiles(scanPath, func(p string) bool {
		_, ok := cveSourceExtensions[strings.ToLower(filepath.Ext(p))]
		return ok
	})
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{} // cve|file|line — one finding per CVE per location
	for _, f := range files {
		lang := cveSourceExtensions[strings.ToLower(filepath.Ext(f))]
		pats := byLang[lang]
		if len(pats) == 0 {
			continue
		}
		body, _, rerr := l.readScanFile("scan_cve_patterns", f)
		if rerr != nil {
			continue
		}
		report.FilesScanned++
		rel, e := filepath.Rel(scanPath, f)
		if e != nil || rel == "" {
			rel = filepath.Base(f)
		}
		for i, line := range strings.Split(string(body), "\n") {
			for _, cp := range pats {
				loc := cp.re.FindStringIndex(line)
				if loc == nil {
					continue
				}
				key := cp.meta.id + "|" + rel + "|" + strconv.Itoa(i+1)
				if seen[key] {
					continue
				}
				seen[key] = true
				report.Findings = append(report.Findings, CVEPatternFinding{
					CVE:        cp.meta.id,
					Name:       cp.meta.name,
					Severity:   cp.meta.severity,
					AttackType: cp.meta.attackType,
					Language:   lang,
					File:       rel,
					Line:       i + 1,
					Pattern:    cp.raw,
					Match:      truncateCVEMatch(line[loc[0]:loc[1]]),
				})
			}
		}
	}
	sortCVEFindings(report.Findings)
	return report, nil
}

func truncateCVEMatch(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > cvePatternMatchMaxLen {
		return s[:cvePatternMatchMaxLen] + "…"
	}
	return s
}

func sortCVEFindings(fs []CVEPatternFinding) {
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		return fs[i].CVE < fs[j].CVE
	})
}

// ScanCVEPatternsSARIF renders a CVE-pattern report as a SARIF 2.1.0 log,
// one rule per CVE. Mirrors the other scanner SARIF transformers.
func ScanCVEPatternsSARIF(rep *CVEReachabilityReport) *SARIFLog {
	if rep == nil {
		return emptyLog("scan_cve_patterns")
	}
	rules := make([]SARIFRule, 0)
	ruleIndex := map[string]int{}
	results := make([]SARIFResult, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		id := "skills-mcp." + f.CVE
		if _, ok := ruleIndex[id]; !ok {
			ruleIndex[id] = len(rules)
			rules = append(rules, SARIFRule{
				ID:               id,
				Name:             f.CVE,
				ShortDescription: &SARIFMultiformat{Text: f.Name},
				DefaultConfig:    &SARIFRuleConfig{Level: sarifLevel(f.Severity)},
			})
		}
		results = append(results, SARIFResult{
			RuleID:    id,
			RuleIndex: ruleIndex[id],
			Level:     sarifLevel(f.Severity),
			Message:   SARIFMultiformat{Text: f.CVE + " (" + f.Name + ") code pattern present: " + f.Match},
			Locations: []SARIFLocation{{
				PhysicalLocation: SARIFPhysicalLocation{
					ArtifactLocation: SARIFArtifactLocation{URI: fileURI(f.File)},
					Region:           &SARIFRegion{StartLine: f.Line},
				},
			}},
			Properties: map[string]any{
				"severity":    f.Severity,
				"cve":         f.CVE,
				"language":    f.Language,
				"attack_type": f.AttackType,
				"pattern":     f.Pattern,
			},
		})
	}
	sortRulesAndResults(rules, ruleIndex, results)
	return sarifLogWithCWE(rules, results)
}
