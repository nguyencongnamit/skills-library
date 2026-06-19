package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/namncqualgo/skills-library/internal/checks"
	"github.com/namncqualgo/skills-library/internal/tools"
)

// CheckResult is the outcome of running one automated check (from the
// internal/checks registry) over the scan target during evidence
// generation (schema 2.0). It is what upgrades a compliance report from
// "the right prevention skills are present" (intent) to "the checks ran
// and this is what they found" (verification).
type CheckResult struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Status   string `json:"status"` // pass | fail | not_run | error
	Findings int    `json:"findings"`
	Detail   string `json:"detail,omitempty"`
}

// Check execution statuses.
const (
	checkPass   = "pass"
	checkFail   = "fail"
	checkNotRun = "not_run"
	checkError  = "error"
)

// Per-control verification verdicts (derived from the control's CheckResults).
const (
	verifiedClean  = "verified"       // every scanner check ran and found nothing
	verifiedFindgs = "findings"       // a scanner check found something to remediate
	notVerifiable  = "not_verifiable" // control cites checks, but none are runnable scanners
	verifyError    = "error"          // a scanner failed to run
)

// runControlChecks executes each scanner-kind check ID over scanPath and
// returns one CheckResult per requested check. Lookup-kind checks (which
// answer a question about a single artifact, not a repository) are recorded
// as not_run — a path scan cannot meaningfully execute them. Unknown IDs
// are skipped; `skills-check validate` already rejects them at authoring
// time, so this only guards against drift.
func runControlChecks(lib *tools.Library, scanPath string, checkIDs []string) []CheckResult {
	out := make([]CheckResult, 0, len(checkIDs))
	for _, id := range checkIDs {
		def, ok := checks.Lookup(id)
		if !ok {
			continue
		}
		cr := CheckResult{ID: id, Kind: string(def.Kind)}
		if def.Kind != checks.KindScanner {
			cr.Status = checkNotRun
			cr.Detail = "lookup check — not executed in a repository scan"
			out = append(out, cr)
			continue
		}
		n, err := runScanner(lib, id, scanPath)
		switch {
		case err != nil:
			cr.Status = checkError
			cr.Detail = err.Error()
		case n > 0:
			cr.Status = checkFail
			cr.Findings = n
		default:
			cr.Status = checkPass
		}
		out = append(out, cr)
	}
	return out
}

// deriveVerification collapses a control's CheckResults into a single
// verdict. Order of precedence: a real finding (something to fix) outranks
// an execution error, which outranks "not verifiable"; only when at least
// one scanner ran and all of them came back clean is the control verified.
func deriveVerification(results []CheckResult) string {
	var ranScanner, sawFinding, sawError, sawCheck bool
	for _, r := range results {
		sawCheck = true
		switch r.Status {
		case checkFail:
			sawFinding = true
			ranScanner = true
		case checkPass:
			ranScanner = true
		case checkError:
			sawError = true
		}
	}
	switch {
	case !sawCheck:
		return "" // control cites no checks — leave unset (skill-only coverage)
	case sawFinding:
		return verifiedFindgs
	case sawError:
		return verifyError
	case ranScanner:
		return verifiedClean
	default:
		return notVerifiable // only lookup/not_run checks
	}
}

// runScanner binds a registered scanner check ID to the library scanner
// that implements it and returns the total finding count over scanPath.
// Files that cannot be parsed (binary, unreadable) are skipped, mirroring
// the `scan` CLI's per-file tolerance, so one bad file never fails a whole
// control's verification.
func runScanner(lib *tools.Library, id, scanPath string) (int, error) {
	switch id {
	case "scan_secrets":
		files, err := tools.WalkScanFiles(scanPath, nil)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, f := range files {
			res, err := lib.ScanSecrets("", f)
			if err != nil {
				continue
			}
			total += len(res.Matches)
		}
		return total, nil

	case "scan_dependencies":
		lockfiles, err := discoverLockfiles(scanPath)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, lf := range lockfiles {
			res, err := lib.ScanDependencies(lf)
			if err != nil {
				continue
			}
			total += len(res.Findings)
		}
		return total, nil

	case "scan_dockerfile":
		files, err := tools.WalkScanFiles(scanPath, isDockerfilePath)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, f := range files {
			res, err := lib.ScanDockerfile(f)
			if err != nil {
				continue
			}
			total += len(res.Findings)
		}
		return total, nil

	case "scan_github_actions":
		files, err := tools.WalkScanFiles(scanPath, isWorkflowPath)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, f := range files {
			res, err := lib.ScanGitHubActions(f)
			if err != nil {
				continue
			}
			total += len(res.Findings)
		}
		return total, nil

	default:
		return 0, fmt.Errorf("no scanner bound for check %q", id)
	}
}

// isDockerfilePath matches Dockerfile / Dockerfile.<x> / *.dockerfile.
func isDockerfilePath(path string) bool {
	b := filepath.Base(path)
	return b == "Dockerfile" ||
		strings.HasPrefix(b, "Dockerfile.") ||
		strings.HasSuffix(strings.ToLower(b), ".dockerfile")
}

// isWorkflowPath matches GitHub Actions workflow YAML under .github/workflows/.
func isWorkflowPath(path string) bool {
	p := filepath.ToSlash(path)
	if !strings.Contains(p, ".github/workflows/") {
		return false
	}
	lb := strings.ToLower(filepath.Base(p))
	return strings.HasSuffix(lb, ".yml") || strings.HasSuffix(lb, ".yaml")
}
