package cmd

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/manifest"
)

func versionCmd() *cobra.Command {
	var path string
	c := &cobra.Command{
		Use:   "version",
		Short: "Print CLI, library, embedded signing key, and Go version",
		RunE: func(c *cobra.Command, args []string) error {
			out := c.OutOrStdout()
			fmt.Fprintf(out, "skills-check %s\n", CLIVersion)
			libVersion := "unknown"
			manifestKey := ""
			if m, err := manifest.Load(filepath.Join(path, "manifest.json")); err == nil {
				libVersion = m.Version
				manifestKey = m.PublicKeyID
			}
			embedded := manifest.EmbeddedKeyDisplay()
			fmt.Fprintf(out, "library    %s\n", libVersion)
			fmt.Fprintf(out, "publickey  %s\n", displayPublicKey(manifestKey, embedded))
			fmt.Fprintf(out, "go         %s\n", runtime.Version())
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", ".", "library root containing manifest.json")
	return c
}

func displayPublicKey(manifestKey, embedded string) string {
	switch {
	case embedded != "" && embedded != "unset" && manifestKey != "" && manifestKey != embedded:
		return fmt.Sprintf("%s (manifest declares %s)", embedded, manifestKey)
	case embedded != "" && embedded != "unset":
		return embedded
	case manifestKey != "":
		return manifestKey
	default:
		return "unset"
	}
}
