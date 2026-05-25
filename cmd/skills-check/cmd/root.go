// Package cmd implements the Cobra command tree for skills-check.
package cmd

import (
	"github.com/spf13/cobra"
)

// CLIVersion is the semantic version of the skills-check binary. It is
// stamped at build time via -ldflags "-X github.com/.../cmd.CLIVersion=...".
var CLIVersion = "0.1.0-dev"

// Root returns the configured root command.
func Root() *cobra.Command {
	root := &cobra.Command{
		Use:   "skills-check",
		Short: "Skills Library command-line tool",
		Long: `skills-check is the Skills Library CLI.

It validates skills, generates IDE-specific configuration files, and pulls
signed updates of vulnerability data and detection rules.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.AddCommand(initCmd())
	root.AddCommand(updateCmd())
	root.AddCommand(validateCmd())
	root.AddCommand(listCmd())
	root.AddCommand(regenerateCmd())
	root.AddCommand(generateNativeCmd())
	root.AddCommand(versionCmd())
	root.AddCommand(manifestCmd())
	root.AddCommand(schedulerCmd())
	root.AddCommand(selfUpdateCmd())
	root.AddCommand(newCmd())
	root.AddCommand(testCmd())
	root.AddCommand(evidenceCmd())
	root.AddCommand(configureCmd())
	root.AddCommand(fetchVulnsCmd())
	return root
}
