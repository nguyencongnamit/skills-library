package tools

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// engineRunTimeout bounds how long an external engine subprocess may
// run before it is killed. Dockerfile/workflow linting is fast; a
// hang almost always means a misbehaving binary, not a slow scan.
const engineRunTimeout = 30 * time.Second

// EngineScanResult is the MCP response for a scan delegated to a named
// external engine. It mirrors the builtin scanner results closely
// enough that a caller can render either the same way.
type EngineScanResult struct {
	Engine   string          `json:"engine"`
	Type     string          `json:"type"`
	Scanner  string          `json:"scanner"`
	FilePath string          `json:"file_path"`
	Findings []EngineFinding `json:"findings"`
}

// RunEngine executes the named external engine for a scanner against
// filePath and returns its parsed findings. It is the execution
// counterpart to ListEngines (discovery): ListEngines tells the caller
// what is available; RunEngine actually runs one.
//
// Security model — RunEngine only ever runs commands that are:
//
//   - declared by a `<!-- engine: … -->` marker in a committed
//     SKILL.md (never an arbitrary caller-supplied command);
//   - of type "external" with a `binary` that resolves on PATH;
//   - invoked as an argv slice (no shell), where the only
//     caller-influenced token is `{file_path}`, which must first pass
//     validateScanPath (absolute, no `..`, outside the sensitive
//     deny-list, and under --allowed-roots when configured);
//   - bounded by engineRunTimeout.
//
// The builtin engine is not handled here — callers route `internal`
// to the in-process scanner (e.g. ScanDockerfile). Asking RunEngine
// for a builtin engine is an error so the two paths can't be confused.
func (l *Library) RunEngine(scanner, engineName, filePath string) (*EngineScanResult, error) {
	markers, err := l.EnginesForScanner(scanner)
	if err != nil {
		return nil, err
	}
	var marker *EngineMarker
	for i := range markers {
		if strings.EqualFold(markers[i].Name, engineName) {
			marker = &markers[i]
			break
		}
	}
	if marker == nil {
		return nil, fmt.Errorf("engine %q is not declared for scanner %q", engineName, scanner)
	}
	if marker.Type != "external" {
		return nil, fmt.Errorf("engine %q is %q, not external; route it to the builtin scanner", engineName, marker.Type)
	}
	return l.runEngineMarker(marker, filePath)
}

// runEngineMarker is the testable core: it trusts that `marker` came
// from the registry (a parsed SKILL.md marker) and runs it against
// filePath. Splitting it out lets unit tests exercise the exec + parse
// path with a stub binary without going through SKILL.md harvesting.
func (l *Library) runEngineMarker(marker *EngineMarker, filePath string) (*EngineScanResult, error) {
	// Reuse the exact same path guard the builtin file scanners use:
	// absolute, no traversal, outside the sensitive deny-list, and
	// under --allowed-roots when configured.
	if err := l.validateScanPath(filePath); err != nil {
		msg := strings.TrimPrefix(err.Error(), "scan_secrets:")
		return nil, fmt.Errorf("engine %s:%s", marker.Name, msg)
	}
	if len(marker.Execute) == 0 {
		return nil, fmt.Errorf("engine %q declares no execute argv", marker.Name)
	}
	bin := marker.Binary
	if bin == "" {
		bin = marker.Execute[0]
	}
	resolved, err := exec.LookPath(bin)
	if err != nil {
		hint := marker.InstallHint
		if hint != "" {
			hint = " (install: " + hint + ")"
		}
		return nil, fmt.Errorf("engine %q binary %q not found on PATH%s", marker.Name, bin, hint)
	}

	// Build the argv: argv[0] is the binary (use the resolved path),
	// the rest are the declared args with {file_path} substituted.
	// filePath is substituted as a single discrete argv element — it
	// never reaches a shell, so spaces / metacharacters in the path
	// cannot inject additional arguments.
	args := make([]string, 0, len(marker.Execute))
	for _, a := range marker.Execute[1:] {
		args = append(args, strings.ReplaceAll(a, "{file_path}", filePath))
	}

	ctx, cancel := context.WithTimeout(context.Background(), engineRunTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, resolved, args...)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("engine %q timed out after %s", marker.Name, engineRunTimeout)
	}

	// Many linters (hadolint included) exit non-zero precisely when
	// they DO find issues, writing the report to stdout. So a non-zero
	// exit is not by itself a failure — only treat it as one when there
	// is no parseable output to show.
	out := strings.TrimSpace(stdout.String())
	if out == "" {
		if runErr != nil {
			return nil, fmt.Errorf("engine %q failed: %v: %s", marker.Name, runErr, strings.TrimSpace(stderr.String()))
		}
		// Clean run, no output → no findings.
		return &EngineScanResult{Engine: marker.Name, Type: marker.Type, Scanner: marker.Scanner, FilePath: filePath, Findings: []EngineFinding{}}, nil
	}

	var findings []EngineFinding
	switch marker.OutputFormat {
	case "sarif":
		findings, err = parseSARIF([]byte(out), marker.Name)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("engine %q has unsupported output_format %q for execution", marker.Name, marker.OutputFormat)
	}

	return &EngineScanResult{
		Engine:   marker.Name,
		Type:     marker.Type,
		Scanner:  marker.Scanner,
		FilePath: filePath,
		Findings: findings,
	}, nil
}
