// skills-check is the Skills Library command-line tool. It validates skills,
// generates IDE-specific configuration files, and pulls signed updates from a
// remote source.
package main

import (
	"fmt"
	"os"

	"github.com/namncqualgo/skills-library/cmd/skills-check/cmd"
)

func main() {
	err := cmd.Root().Execute()
	if err == nil {
		return
	}
	if cmd.IsPolicyFailure(err) {
		// A gate finding met the severity floor. This is a policy
		// result, not an operational failure: the report (text / json /
		// sarif) is already on stdout, so we only echo the one-line
		// summary and exit 1 — the documented "gate failed" signal CI
		// and pre-commit consumers key on. Keeping this distinct from
		// the exit-2 path below lets a CI wrapper still upload the SARIF
		// it just produced before failing the build.
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	// Anything else is an operational error (bad flag, missing file,
	// unreadable rule data). Exit 2 so callers can tell a real failure
	// apart from a clean policy rejection.
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
