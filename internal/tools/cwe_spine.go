package tools

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/namncqualgo/skills-library/internal/checks"
)

// cweInputRegex accepts a CWE identifier in either canonical ("CWE-79") or
// bare-number ("79") form, case-insensitively, so callers (and LLMs) need not
// remember the exact prefix casing.
var cweInputRegex = regexp.MustCompile(`^(?i:cwe-)?([0-9]+)$`)

// CWESpineResult is the cross-framework view of a single CWE: the join that
// turns one weakness identifier into the controls that guard against it (in
// every mapped framework), the prevention skills that advise on those
// controls, and the runnable checks that detect or verify it. It is the CF.7
// spine — one finding's CWE auto-surfaces its controls → skills → checks —
// and the seed for the knowledge graph (Phase 4).
type CWESpineResult struct {
	CWE string `json:"cwe"`
	// Frameworks holds the controls that cite this CWE, keyed by the same
	// machine framework ID used by map_compliance_control ("soc2", "slsa", …).
	Frameworks map[string]CWEFrameworkMatch `json:"frameworks"`
	// ControlCount is the total number of controls citing this CWE across all
	// frameworks (a quick "how broadly does this weakness matter" signal).
	ControlCount int `json:"control_count"`
	// Skills is the sorted union of prevention skill IDs advised by the
	// matching controls.
	Skills []string `json:"skills"`
	// Checks is the sorted union of runnable check IDs that detect or verify
	// this CWE: registry checks tagged with the CWE plus checks cited by the
	// matching controls.
	Checks []string `json:"checks"`
	// Rules is the detection (Sigma) rules tagged with this CWE — the
	// runtime/behavioral leg of the spine. A weakness's exploitation can be
	// *detected* at runtime (a Sigma rule), not only prevented (a skill) or
	// statically verified (a check). Sorted by rule path; never null.
	Rules []CWERuleRef `json:"rules"`
}

// CWERuleRef identifies one detection (Sigma) rule tagged with the CWE.
type CWERuleRef struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
	Level    string `json:"level,omitempty"`
	Path     string `json:"path"`
}

// CWEFrameworkMatch is the set of one framework's controls that cite a CWE.
type CWEFrameworkMatch struct {
	Name     string          `json:"name"`
	Controls []CWEControlRef `json:"controls"`
}

// CWEControlRef identifies one control that cites the CWE.
type CWEControlRef struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// NormalizeCWE canonicalises a user-supplied CWE identifier to the form
// "CWE-<number>" (e.g. "cwe-79" or "79" → "CWE-79"). It returns an error for
// anything that is not a CWE number so a typo fails loudly rather than
// silently matching nothing.
func NormalizeCWE(raw string) (string, error) {
	m := cweInputRegex.FindStringSubmatch(strings.TrimSpace(raw))
	if m == nil {
		return "", fmt.Errorf("invalid CWE %q (want \"CWE-<number>\" or \"<number>\")", raw)
	}
	return "CWE-" + m[1], nil
}

// MapCWE resolves a CWE identifier to its cross-framework spine: every control
// that cites it (grouped by framework), the union of prevention skills those
// controls advise, the union of runnable checks that detect or verify it, and
// the detection (Sigma) rules that catch its exploitation at runtime. An
// unknown-but-well-formed CWE returns an empty (non-nil) result rather than an
// error, so callers can use it to ask "is this weakness covered?".
func (l *Library) MapCWE(rawCWE string) (*CWESpineResult, error) {
	cwe, err := NormalizeCWE(rawCWE)
	if err != nil {
		return nil, err
	}
	out := &CWESpineResult{
		CWE:        cwe,
		Frameworks: map[string]CWEFrameworkMatch{},
		Rules:      []CWERuleRef{},
	}
	skillSet := map[string]bool{}
	checkSet := map[string]bool{}

	// Leg 1: registry checks directly tagged with this CWE.
	for _, id := range checks.ByCWE(cwe) {
		checkSet[id] = true
	}

	// Legs 2–4: controls citing the CWE, plus their skills and checks.
	for _, fwKey := range frameworkOrder {
		mapping, err := l.loadCompliance(fwKey)
		if err != nil {
			continue
		}
		var refs []CWEControlRef
		for _, ctrl := range mapping.Controls {
			if !containsFold(ctrl.CWE, cwe) {
				continue
			}
			refs = append(refs, CWEControlRef{ID: ctrl.ID, Title: ctrl.Title})
			for _, s := range ctrl.Skills {
				if s = strings.TrimSpace(s); s != "" {
					skillSet[s] = true
				}
			}
			for _, c := range ctrl.Checks {
				if c = strings.TrimSpace(c); c != "" {
					checkSet[c] = true
				}
			}
		}
		if refs != nil {
			out.Frameworks[fwKey] = CWEFrameworkMatch{Name: mapping.Framework, Controls: refs}
			out.ControlCount += len(refs)
		}
	}

	// Leg 5: detection (Sigma) rules tagged with this CWE via a "cwe.<n>"
	// tag. Loaded lazily; a rules read error degrades to no detection leg
	// rather than failing the whole spine query.
	cweNum := strings.TrimPrefix(cwe, "CWE-")
	if rules, err := l.loadSigmaRules(); err == nil {
		for _, r := range rules {
			if ruleTagsHaveCWE(r.Tags, cweNum) {
				out.Rules = append(out.Rules, CWERuleRef{
					ID:       r.ID,
					Title:    r.Title,
					Category: r.Category,
					Level:    r.Level,
					Path:     r.Path,
				})
			}
		}
	}

	out.Skills = sortedKeys(skillSet)
	out.Checks = sortedKeys(checkSet)
	return out, nil
}

// ruleTagsHaveCWE reports whether a Sigma rule's tags include the given CWE
// number written in the Sigma convention "cwe.<number>" (case-insensitive).
func ruleTagsHaveCWE(tags []string, cweNum string) bool {
	want := "cwe." + cweNum
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), want) {
			return true
		}
	}
	return false
}

// containsFold reports whether s contains target, comparing case-insensitively
// (CWE IDs are upper-case canonically, but a hand-edited mapping might not be).
func containsFold(s []string, target string) bool {
	for _, v := range s {
		if strings.EqualFold(strings.TrimSpace(v), target) {
			return true
		}
	}
	return false
}

// sortedKeys returns the set's keys as a sorted slice (never nil, so JSON
// marshals as [] not null).
func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
