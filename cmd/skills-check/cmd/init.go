package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/compiler"
	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/scheduler"
	"github.com/kennguy3n/skills-library/internal/skill"
)

func initCmd() *cobra.Command {
	var libraryPath, tool, skillsList, budget, outDir, profileName string
	var noPrompt, fullInline, legacy bool
	c := &cobra.Command{
		Use:   "init",
		Short: "Generate an IDE-specific config file in the current project",
		RunE: func(c *cobra.Command, args []string) error {
			if tool == "" {
				return fmt.Errorf("--tool is required")
			}
			f, ok := compiler.Registry[tool]
			if !ok {
				return fmt.Errorf("unknown tool %q", tool)
			}
			tier := f.DefaultTier()
			if budget != "" {
				if !skill.IsValidTier(budget) {
					return fmt.Errorf("invalid budget %q (valid: minimal, compact, full)", budget)
				}
				tier = skill.Tier(budget)
			}

			lib, err := filepath.Abs(libraryPath)
			if err != nil {
				return err
			}
			all, err := skill.LoadAll(filepath.Join(lib, "skills"))
			if err != nil {
				return err
			}
			// --skills and --profile compose as an intersection: both
			// filters apply, narrowing the skill set to those present in
			// both. Setting only one (or neither) collapses cleanly. See
			// filterSkillsBySkillList / compiler.FilterSkillsByProfile.
			if skillsList != "" {
				all = filterSkillsBySkillList(all, skillsList)
				if len(all) == 0 {
					return fmt.Errorf("no skills matched %q", skillsList)
				}
			}
			if profileName != "" {
				prof, err := compiler.LoadProfile(lib, profileName)
				if err != nil {
					return err
				}
				all = compiler.FilterSkillsByProfile(all, prof)
				if len(all) == 0 {
					return fmt.Errorf("profile %q matched no skills", profileName)
				}
			}

			ctx, err := compiler.LoadContext(lib)
			if err != nil {
				return err
			}
			// --full-inline (alias --legacy) restores the pre-v2
			// monolithic per-tool dist/ output that inlines every skill
			// body. Mirrors the same flag on `regenerate` so operators
			// have parity between the two entry points; without it,
			// every per-tool file now emits the minimal pointer file by
			// default. The universal SECURITY-SKILLS.md surface is the
			// exception and always inlines, regardless of this flag.
			if fullInline || legacy {
				ctx.FullInline = true
			}
			if outDir == "" {
				outDir, err = os.Getwd()
				if err != nil {
					return err
				}
			}
			report, warns, err := compiler.WriteFile(all, tool, tier, ctx, outDir)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "wrote %s (%s tier, %d skills, %d openai / %d claude tokens)\n",
				filepath.Join(outDir, f.OutputName()), tier, len(all), report.Total.OpenAI, report.Total.Claude)
			for _, w := range warns {
				fmt.Fprintln(c.ErrOrStderr(), "warn:", w)
			}

			if !noPrompt {
				maybeOfferScheduler(c.InOrStdin(), out)
			}
			return nil
		},
	}
	c.Flags().StringVar(&libraryPath, "library", ".", "path to the skills-library checkout")
	c.Flags().StringVar(&tool, "tool", "", "target tool (claude|cursor|copilot|codex|agents|windsurf|devin|cline|universal)")
	c.Flags().StringVar(&skillsList, "skills", "", "comma-separated skill IDs (narrows the --profile selection when combined; both filters apply)")
	c.Flags().StringVar(&budget, "budget", "", "tier override (minimal|compact|full)")
	c.Flags().StringVar(&outDir, "out", "", "output directory (default: cwd)")
	c.Flags().BoolVar(&noPrompt, "no-prompt", false, "skip the interactive prompt to set up scheduled updates")
	c.Flags().StringVar(&profileName, "profile", "", "enterprise profile (e.g., financial-services|healthcare|government) — restricts the skill set")
	c.Flags().BoolVar(&fullInline, "full-inline", false, "render the legacy monolithic per-tool dist/ output that inlines every skill body (default is the minimal pointer file)")
	c.Flags().BoolVar(&legacy, "legacy", false, "alias for --full-inline")
	return c
}

// filterSkillsBySkillList returns only those skills whose ID appears in
// the comma-separated `skillsList` (whitespace around each ID is trimmed).
// The returned slice is freshly allocated; the caller's `all` slice and
// its backing array are never mutated, so this function composes safely
// with compiler.FilterSkillsByProfile when both --skills and --profile are
// set (intersection semantics).
func filterSkillsBySkillList(all []*skill.Skill, skillsList string) []*skill.Skill {
	want := map[string]bool{}
	for _, s := range strings.Split(skillsList, ",") {
		want[strings.TrimSpace(s)] = true
	}
	out := make([]*skill.Skill, 0, len(all))
	for _, s := range all {
		if want[s.Frontmatter.ID] {
			out = append(out, s)
		}
	}
	return out
}

// maybeOfferScheduler asks the operator whether to install the background
// scheduled-update task. It is a no-op when the scheduler is already
// installed, when stdin is not a TTY, or when the user answers anything
// other than "y" / "yes".
func maybeOfferScheduler(stdin io.Reader, out io.Writer) {
	status, err := scheduler.Status()
	if err == nil && status != "" {
		return
	}
	if !isTerminal(stdin) {
		return
	}
	fmt.Fprint(out, "Would you like to set up automatic background updates? [y/N] ")
	reader := bufio.NewReader(stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	if answer != "y" && answer != "yes" {
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(out, "could not resolve current binary: %v\n", err)
		return
	}
	if err := scheduler.Install(scheduler.Defaults(exe)); err != nil {
		fmt.Fprintf(out, "scheduler install failed: %v\n", err)
		return
	}
	fmt.Fprintln(out, "scheduled update installed; run `skills-check scheduler status` to inspect")
}

func isTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
