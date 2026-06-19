package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/namncqualgo/skills-library/internal/compliance"
	"github.com/namncqualgo/skills-library/internal/skill"
	"github.com/namncqualgo/skills-library/internal/tools"
)

// frameworkSlugRegex restricts the --framework value to a simple slug so the
// derived mapping path (compliance/<slug>_mapping.yaml) can never traverse
// out of the compliance/ directory or pull in unintended files.
var frameworkSlugRegex = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ComplianceMapping is the shape of the per-framework mapping files under
// compliance/<framework>_mapping.yaml. The canonical definition lives in
// internal/compliance (shared with the library's map_compliance_control
// tool) so the on-disk shape cannot drift between the two consumers.
type ComplianceMapping = compliance.Mapping

// EvidenceReport is the rendered audit artifact for `skills-check evidence`.
type EvidenceReport struct {
	GeneratedAt      time.Time `json:"generated_at"`
	Framework        string    `json:"framework"`
	FrameworkVersion string    `json:"framework_version,omitempty"`
	LibraryRoot      string    `json:"library_root"`
	// ScanTarget is the path whose code the mapped checks were run against
	// (set only when --scan was passed). Empty means a skill-coverage-only
	// report with no verification.
	ScanTarget       string            `json:"scan_target,omitempty"`
	SkillsCount      int               `json:"skills_count"`
	Controls         []ControlEvidence `json:"controls"`
	UnmappedSkills   []string          `json:"unmapped_skills"`
	UnmappedControls []string          `json:"unmapped_controls"`
	Metadata         map[string]string `json:"metadata,omitempty"`
}

type ControlEvidence struct {
	ID            string         `json:"id"`
	Title         string         `json:"title"`
	Description   string         `json:"description,omitempty"`
	Status        string         `json:"status"` // covered | partial | missing | unmapped
	MappedSkills  []string       `json:"mapped_skills"`
	PresentSkills []SkillSummary `json:"present_skills"`
	MissingSkills []string       `json:"missing_skills"`
	// MappedChecks / CWE are the schema-2.0 automated checks and weakness
	// IDs the mapping ties to this control.
	MappedChecks []string `json:"mapped_checks,omitempty"`
	CWE          []string `json:"cwe,omitempty"`
	// Verification and CheckResults are populated only when --scan ran the
	// mapped checks over a target: Verification is the collapsed verdict
	// (verified | findings | not_verifiable | error), CheckResults the
	// per-check detail. Empty when no scan was requested (skill-only report).
	Verification string        `json:"verification,omitempty"`
	CheckResults []CheckResult `json:"check_results,omitempty"`
	References   []string      `json:"references,omitempty"`
}

type SkillSummary struct {
	ID          string `json:"id"`
	Version     string `json:"version"`
	LastUpdated string `json:"last_updated"`
	Path        string `json:"path"`
}

func evidenceCmd() *cobra.Command {
	var (
		libraryPath string
		framework   string
		format      string
		outFile     string
		scanPath    string
	)

	c := &cobra.Command{
		Use:   "evidence",
		Short: "Emit a compliance coverage report showing which installed skills map to framework controls",
		Long: `Compile a compliance coverage report that maps installed skills onto
the controls of a compliance framework (SOC2, HIPAA, PCI-DSS).

The report is timestamped and lists which controls are covered by which skill
versions, flagging missing skills — showing which installed skills map to
framework controls. It is a developer-facing coverage map, not an audit
artifact: a real audit also needs runtime evidence, change-management
records, access reviews, and so on.
`,
		RunE: func(c *cobra.Command, args []string) error {
			if framework == "" {
				return fmt.Errorf("--framework is required (SOC2|HIPAA|PCI-DSS)")
			}
			if !frameworkSlugRegex.MatchString(framework) {
				return fmt.Errorf(
					"--framework %q is invalid: must match %s (no path separators or '..')",
					framework, frameworkSlugRegex.String(),
				)
			}
			fwSlug := strings.ToLower(framework)
			fwSlug = strings.ReplaceAll(fwSlug, "-", "_")

			lib, err := filepath.Abs(libraryPath)
			if err != nil {
				return err
			}

			mappingPath := filepath.Join(lib, "compliance", fwSlug+"_mapping.yaml")
			mapData, err := os.ReadFile(mappingPath)
			if err != nil {
				return fmt.Errorf("read mapping for %s: %w (expected %s)", framework, err, mappingPath)
			}
			var mapping ComplianceMapping
			if err := yaml.Unmarshal(mapData, &mapping); err != nil {
				return fmt.Errorf("parse mapping: %w", err)
			}
			if mapping.SchemaVersion == "" {
				return fmt.Errorf("mapping %s missing schema_version", mappingPath)
			}

			skills, err := skill.LoadAll(filepath.Join(lib, "skills"))
			if err != nil {
				return err
			}
			byID := map[string]*skill.Skill{}
			for _, s := range skills {
				byID[s.Frontmatter.ID] = s
			}

			report := EvidenceReport{
				GeneratedAt:      time.Now().UTC(),
				Framework:        mapping.Framework,
				FrameworkVersion: mapping.Version,
				LibraryRoot:      lib,
				SkillsCount:      len(skills),
				Controls:         make([]ControlEvidence, 0, len(mapping.Controls)),
				// Pre-initialize so empty reports marshal as `[]` not `null` (audit JSON shape).
				UnmappedSkills:   []string{},
				UnmappedControls: []string{},
				Metadata: map[string]string{
					"mapping_schema_version": mapping.SchemaVersion,
					"mapping_last_updated":   mapping.LastUpdated,
				},
			}

			// When --scan is set, build a library rooted at the skills/vuln
			// data and run each control's mapped checks over the target so
			// coverage can be VERIFIED, not just asserted from skill presence.
			var scanLib *tools.Library
			if scanPath != "" {
				scanAbs, err := filepath.Abs(scanPath)
				if err != nil {
					return err
				}
				info, err := os.Stat(scanAbs)
				if err != nil {
					return fmt.Errorf("scan target: %w", err)
				}
				if !info.IsDir() {
					return fmt.Errorf("scan target %s must be a directory", scanAbs)
				}
				scanLib, err = tools.NewLibrary(lib)
				if err != nil {
					return fmt.Errorf("open library for scan: %w", err)
				}
				report.ScanTarget = scanAbs
			}

			referencedSkills := map[string]bool{}
			for _, ctrl := range mapping.Controls {
				ev := ControlEvidence{
					ID:           ctrl.ID,
					Title:        ctrl.Title,
					Description:  ctrl.Description,
					MappedSkills: append([]string{}, ctrl.Skills...),
					MappedChecks: append([]string{}, ctrl.Checks...),
					CWE:          append([]string{}, ctrl.CWE...),
					References:   append([]string{}, ctrl.References...),
					// Pre-initialize so per-control JSON marshals as `[]` not `null` when empty.
					PresentSkills: []SkillSummary{},
					MissingSkills: []string{},
				}
				for _, sid := range ctrl.Skills {
					referencedSkills[sid] = true
					if s, ok := byID[sid]; ok {
						ev.PresentSkills = append(ev.PresentSkills, SkillSummary{
							ID:          s.Frontmatter.ID,
							Version:     s.Frontmatter.Version,
							LastUpdated: s.Frontmatter.LastUpdated,
							Path:        s.Path,
						})
					} else {
						ev.MissingSkills = append(ev.MissingSkills, sid)
					}
				}
				switch {
				case len(ev.MappedSkills) == 0:
					ev.Status = "unmapped"
				case len(ev.MissingSkills) == 0:
					ev.Status = "covered"
				case len(ev.PresentSkills) == 0:
					ev.Status = "missing"
				default:
					ev.Status = "partial"
				}
				if scanLib != nil && len(ev.MappedChecks) > 0 {
					ev.CheckResults = runControlChecks(scanLib, report.ScanTarget, ev.MappedChecks)
					ev.Verification = deriveVerification(ev.CheckResults)
				}
				report.Controls = append(report.Controls, ev)
			}

			for _, s := range skills {
				if !referencedSkills[s.Frontmatter.ID] {
					report.UnmappedSkills = append(report.UnmappedSkills, s.Frontmatter.ID)
				}
			}
			sort.Strings(report.UnmappedSkills)

			for _, ctrl := range report.Controls {
				if ctrl.Status == "unmapped" {
					report.UnmappedControls = append(report.UnmappedControls, ctrl.ID)
				}
			}
			sort.Strings(report.UnmappedControls)

			out, err := renderEvidence(report, format)
			if err != nil {
				return err
			}
			if outFile == "" || outFile == "-" {
				fmt.Fprint(c.OutOrStdout(), out)
			} else {
				if err := os.MkdirAll(filepath.Dir(outFile), 0o755); err != nil {
					return err
				}
				if err := os.WriteFile(outFile, []byte(out), 0o644); err != nil {
					return err
				}
				fmt.Fprintf(c.OutOrStdout(), "wrote evidence report to %s (%d controls)\n", outFile, len(report.Controls))
			}
			return nil
		},
	}

	c.Flags().StringVar(&libraryPath, "library", ".", "Path to the skills library root")
	c.Flags().StringVar(&scanPath, "scan", "", "Path to a codebase to VERIFY each control's mapped checks against (schema 2.0); omit for a skill-coverage-only report")
	c.Flags().StringVar(&framework, "framework", "", "Compliance framework: SOC2|HIPAA|PCI-DSS")
	c.Flags().StringVar(&format, "format", "json", "Output format: json|markdown")
	c.Flags().StringVar(&outFile, "out", "", "Write report to this file; '-' or empty for stdout")
	return c
}

func renderEvidence(r EvidenceReport, format string) (string, error) {
	switch strings.ToLower(format) {
	case "json", "":
		b, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			return "", err
		}
		return string(b) + "\n", nil
	case "markdown", "md":
		return renderEvidenceMarkdown(r), nil
	default:
		return "", fmt.Errorf("unknown format %q (valid: json|markdown)", format)
	}
}

func renderEvidenceMarkdown(r EvidenceReport) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Compliance Evidence Report — %s\n\n", r.Framework)
	if r.FrameworkVersion != "" {
		fmt.Fprintf(&sb, "**Framework version:** %s  \n", r.FrameworkVersion)
	}
	fmt.Fprintf(&sb, "**Generated:** %s  \n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Fprintf(&sb, "**Library root:** `%s`  \n", r.LibraryRoot)
	scanning := r.ScanTarget != ""
	if scanning {
		fmt.Fprintf(&sb, "**Scan target:** `%s`  \n", r.ScanTarget)
	}
	fmt.Fprintf(&sb, "**Skills installed:** %d  \n", r.SkillsCount)
	fmt.Fprintf(&sb, "**Controls evaluated:** %d\n\n", len(r.Controls))

	var covered, partial, missing, unmapped int
	verif := map[string]int{}
	for _, c := range r.Controls {
		switch c.Status {
		case "covered":
			covered++
		case "partial":
			partial++
		case "missing":
			missing++
		case "unmapped":
			unmapped++
		}
		if c.Verification != "" {
			verif[c.Verification]++
		}
	}
	fmt.Fprintf(&sb, "## Summary\n\n- Covered: %d\n- Partial: %d\n- Missing: %d\n- Unmapped: %d\n", covered, partial, missing, unmapped)
	if scanning {
		fmt.Fprintf(&sb, "\n**Verification (checks run against the scan target):**\n\n- Verified: %d\n- Findings: %d\n- Not verifiable: %d\n- Errors: %d\n",
			verif[verifiedClean], verif[verifiedFindgs], verif[notVerifiable], verif[verifyError])
	}
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "## Controls\n\n")
	if scanning {
		fmt.Fprintf(&sb, "| Control | Status | Verification | Checks | Skills present | Skills missing |\n")
		fmt.Fprintf(&sb, "|---|---|---|---|---|---|\n")
	} else {
		fmt.Fprintf(&sb, "| Control | Status | Skills present | Skills missing |\n")
		fmt.Fprintf(&sb, "|---|---|---|---|\n")
	}
	for _, c := range r.Controls {
		present := make([]string, 0, len(c.PresentSkills))
		for _, s := range c.PresentSkills {
			present = append(present, escapeMarkdownTableCell(fmt.Sprintf("%s@%s", s.ID, s.Version)))
		}
		missing := make([]string, 0, len(c.MissingSkills))
		for _, m := range c.MissingSkills {
			missing = append(missing, escapeMarkdownTableCell(m))
		}
		if scanning {
			checkCells := make([]string, 0, len(c.CheckResults))
			for _, cr := range c.CheckResults {
				label := fmt.Sprintf("%s:%s", cr.ID, cr.Status)
				if cr.Findings > 0 {
					label = fmt.Sprintf("%s(%d)", label, cr.Findings)
				}
				checkCells = append(checkCells, escapeMarkdownTableCell(label))
			}
			fmt.Fprintf(&sb, "| %s | %s | %s | %s | %s | %s |\n",
				escapeMarkdownTableCell(c.ID),
				escapeMarkdownTableCell(c.Status),
				escapeMarkdownTableCell(c.Verification),
				strings.Join(checkCells, ", "),
				strings.Join(present, ", "),
				strings.Join(missing, ", "))
		} else {
			fmt.Fprintf(&sb, "| %s | %s | %s | %s |\n",
				escapeMarkdownTableCell(c.ID),
				escapeMarkdownTableCell(c.Status),
				strings.Join(present, ", "),
				strings.Join(missing, ", "))
		}
	}
	if len(r.UnmappedSkills) > 0 {
		fmt.Fprintf(&sb, "\n## Skills not referenced by any control\n\n")
		for _, s := range r.UnmappedSkills {
			fmt.Fprintf(&sb, "- %s\n", s)
		}
	}
	if len(r.UnmappedControls) > 0 {
		fmt.Fprintf(&sb, "\n## Controls with no mapped skills\n\n")
		for _, id := range r.UnmappedControls {
			fmt.Fprintf(&sb, "- %s\n", id)
		}
	}
	return sb.String()
}

// escapeMarkdownTableCell escapes characters that would break a GFM table
// row when interpolated as a cell value: pipes terminate columns and
// newlines terminate rows. Future compliance frameworks may emit control
// IDs or skill identifiers that contain these characters; today's data
// does not, so this is a robustness fix rather than a fix for current
// breakage.
func escapeMarkdownTableCell(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "|", `\|`)
	s = strings.ReplaceAll(s, "\r\n", "<br>")
	s = strings.ReplaceAll(s, "\n", "<br>")
	s = strings.ReplaceAll(s, "\r", "<br>")
	return s
}
