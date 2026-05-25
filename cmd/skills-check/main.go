// skills-check is the Skills Library command-line tool. It validates skills,
// generates IDE-specific configuration files, and pulls signed updates from a
// remote source.
package main

import (
	"fmt"
	"os"

	"github.com/kennguy3n/skills-library/cmd/skills-check/cmd"
)

func main() {
	if err := cmd.Root().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
