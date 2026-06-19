package cmd

import (
	"github.com/namncqualgo/skills-library/internal/checks"
)

// CheckResult is the per-check evidence row rendered in the report. It is an
// alias for the canonical checks.Result so the evidence bundle, the
// map_compliance_control --run response, and the runner all share one shape
// and can never drift. The execution itself lives in
// (*tools.Library).RunControlChecks — there is exactly one implementation.
type CheckResult = checks.Result

// Check execution statuses (aliases of the canonical checks constants so
// existing call sites and tests in this package keep compiling).
const (
	checkPass   = checks.StatusPass
	checkFail   = checks.StatusFail
	checkNotRun = checks.StatusNotRun
	checkError  = checks.StatusError
)

// Per-control verification verdicts (aliases of the canonical checks
// constants), used by the markdown renderer's summary counters.
const (
	verifiedClean  = checks.VerdictVerified
	verifiedFindgs = checks.VerdictFindings
	notVerifiable  = checks.VerdictNotVerifiable
	verifyError    = checks.VerdictError
)

// deriveVerification collapses a control's CheckResults into a single verdict.
// It delegates to checks.Verdict so the CLI and the MCP tool agree.
func deriveVerification(results []CheckResult) string {
	return checks.Verdict(results)
}
