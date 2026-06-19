package checks

// Result is the outcome of running one registered check (see the registry)
// over a target path. It is what upgrades a compliance report from "the
// right prevention skills are present" (intent) to "the checks ran and this
// is what they found" (verification). The JSON shape is stable: it is
// embedded verbatim in the signed evidence bundle and the
// map_compliance_control --run response, so field names must not change.
type Result struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Status   string `json:"status"` // pass | fail | not_run | error
	Findings int    `json:"findings"`
	Detail   string `json:"detail,omitempty"`
}

// Per-check execution statuses.
const (
	StatusPass   = "pass"    // a scanner ran and found nothing
	StatusFail   = "fail"    // a scanner ran and found something to remediate
	StatusNotRun = "not_run" // a lookup check, not executable in a path scan
	StatusError  = "error"   // the check failed to run
)

// Per-control verification verdicts, derived from a control's Results by
// Verdict. A control is only "verified" when at least one scanner actually
// ran and every scanner came back clean.
const (
	VerdictVerified      = "verified"       // every scanner check ran and found nothing
	VerdictFindings      = "findings"       // a scanner check found something to remediate
	VerdictNotVerifiable = "not_verifiable" // control cites checks, but none are runnable scanners
	VerdictError         = "error"          // a scanner failed to run
)

// Verdict collapses a control's per-check Results into a single verification
// verdict. Order of precedence: a real finding (something to fix) outranks
// an execution error, which outranks "not verifiable"; only when at least
// one scanner ran and all of them came back clean is the control verified.
// An empty result set (the control cites no checks) returns "" so a
// skill-only control is left unverified rather than mislabelled.
func Verdict(results []Result) string {
	var ranScanner, sawFinding, sawError, sawCheck bool
	for _, r := range results {
		sawCheck = true
		switch r.Status {
		case StatusFail:
			sawFinding = true
			ranScanner = true
		case StatusPass:
			ranScanner = true
		case StatusError:
			sawError = true
		}
	}
	switch {
	case !sawCheck:
		return ""
	case sawFinding:
		return VerdictFindings
	case sawError:
		return VerdictError
	case ranScanner:
		return VerdictVerified
	default:
		return VerdictNotVerifiable // only lookup / not_run checks
	}
}
