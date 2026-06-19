package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/namncqualgo/skills-library/internal/tools"
)

// cweCmd is the terminal surface of the CF.7 CWE cross-framework spine. It is
// a thin adapter over (*tools.Library).MapCWE — the same join the map_cwe MCP
// tool exposes — so a developer can run `skills-check cwe CWE-798` and see
// every compliance control that weakness implicates, the prevention skills
// that advise on it, and the runnable checks that verify remediation.
func cweCmd() *cobra.Command {
	var repoPath, format string
	c := &cobra.Command{
		Use:   "cwe <CWE-id>",
		Short: "Resolve a CWE to the controls, skills, and checks that cover it (cross-framework spine)",
		Long: `Resolve a CWE identifier to its cross-framework spine: every compliance
control that cites it (grouped by framework), the prevention skills that
advise on those controls, and the runnable checks that detect or verify it.

The CWE may be given canonically or as a bare number (CWE-798 or 798).`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			if err := validateFormat(format, false); err != nil {
				return err
			}
			lib, err := newLibraryForCmd(repoPath, "", "")
			if err != nil {
				return err
			}
			res, err := lib.MapCWE(args[0])
			if err != nil {
				return err
			}
			if format == "json" {
				return emitJSON(c.OutOrStdout(), res)
			}
			renderCWEText(c, res)
			return nil
		},
	}
	c.Flags().StringVar(&repoPath, "path", ".", "skills-library checkout (default: $SKILLS_LIBRARY_PATH, else cwd)")
	addFormatFlag(c, &format, false)
	return c
}

func renderCWEText(c *cobra.Command, res *tools.CWESpineResult) {
	w := c.OutOrStdout()
	fmt.Fprintf(w, "=== %s ===\n", res.CWE)
	fmt.Fprintf(w, "Controls: %d across %d framework(s)\n", res.ControlCount, len(res.Frameworks))
	if len(res.Skills) > 0 {
		fmt.Fprintf(w, "Skills:   %s\n", strings.Join(res.Skills, ", "))
	}
	if len(res.Checks) > 0 {
		fmt.Fprintf(w, "Checks:   %s\n", strings.Join(res.Checks, ", "))
	}
	if res.ControlCount == 0 {
		fmt.Fprintf(w, "\nNo mapped controls cite %s yet.\n", res.CWE)
		return
	}
	// Deterministic framework order for stable output.
	keys := make([]string, 0, len(res.Frameworks))
	for k := range res.Frameworks {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fm := res.Frameworks[k]
		fmt.Fprintf(w, "\n%s (%s):\n", k, fm.Name)
		for _, ctrl := range fm.Controls {
			fmt.Fprintf(w, "  - %s  %s\n", ctrl.ID, ctrl.Title)
		}
	}
}
