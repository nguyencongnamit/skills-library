package tools

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/namncqualgo/skills-library/internal/checks"
	"github.com/namncqualgo/skills-library/internal/tools/parsers"
)

// RunControlChecks executes each registered check ID over scanPath and
// returns one checks.Result per requested ID. It is the single source of
// truth for "run a control's mapped checks against real code", shared by the
// `skills-check evidence --scan` CLI and the map_compliance_control --run MCP
// tool so the two can never disagree about what a check found.
//
// Lookup-kind checks (which answer a question about a single artifact, not a
// repository) are recorded as not_run — a path scan cannot meaningfully
// execute them. Unknown IDs are skipped; `skills-check validate` already
// rejects them at authoring time, so this only guards against drift.
func (l *Library) RunControlChecks(scanPath string, checkIDs []string) []checks.Result {
	out := make([]checks.Result, 0, len(checkIDs))
	for _, id := range checkIDs {
		def, ok := checks.Lookup(id)
		if !ok {
			continue
		}
		cr := checks.Result{ID: id, Kind: string(def.Kind)}
		if def.Kind != checks.KindScanner {
			cr.Status = checks.StatusNotRun
			cr.Detail = "lookup check — not executed in a repository scan"
			out = append(out, cr)
			continue
		}
		n, err := l.runScannerCheck(id, scanPath)
		switch {
		case err != nil:
			cr.Status = checks.StatusError
			cr.Detail = err.Error()
		case n > 0:
			cr.Status = checks.StatusFail
			cr.Findings = n
		default:
			cr.Status = checks.StatusPass
		}
		out = append(out, cr)
	}
	return out
}

// runScannerCheck binds a registered scanner check ID to the Library scanner
// that implements it and returns the total finding count over scanPath.
// Files that cannot be parsed (binary, unreadable) are skipped, mirroring the
// `scan` CLI's per-file tolerance, so one bad file never fails a whole
// control's verification.
func (l *Library) runScannerCheck(id, scanPath string) (int, error) {
	switch id {
	case "scan_secrets":
		files, err := WalkScanFiles(scanPath, nil)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, f := range files {
			res, err := l.ScanSecrets("", f)
			if err != nil {
				continue
			}
			total += len(res.Matches)
		}
		return total, nil

	case "scan_dependencies":
		lockfiles, err := DiscoverLockfiles(scanPath)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, lf := range lockfiles {
			res, err := l.ScanDependencies(lf)
			if err != nil {
				continue
			}
			total += len(res.Findings)
		}
		return total, nil

	case "scan_dockerfile":
		files, err := WalkScanFiles(scanPath, isDockerfilePath)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, f := range files {
			res, err := l.ScanDockerfile(f)
			if err != nil {
				continue
			}
			total += len(res.Findings)
		}
		return total, nil

	case "scan_github_actions":
		files, err := WalkScanFiles(scanPath, isWorkflowPath)
		if err != nil {
			return 0, err
		}
		total := 0
		for _, f := range files {
			res, err := l.ScanGitHubActions(f)
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

// DiscoverLockfiles returns the paths of every recognised dependency
// manifest / lockfile under dir, using parsers.IsKnownLockfile as the single
// source of truth for which base names are parseable.
func DiscoverLockfiles(dir string) ([]string, error) {
	found, err := WalkScanFiles(dir, func(path string) bool {
		return parsers.IsKnownLockfile(filepath.Base(path))
	})
	if err != nil {
		return nil, fmt.Errorf("discover lockfiles under %s: %w", dir, err)
	}
	return found, nil
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
