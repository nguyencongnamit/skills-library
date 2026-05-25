// skills-mcp serves the Skills Library over the Model Context Protocol.
//
// Transport: JSON-RPC 2.0 over stdio. One JSON-RPC message per line.
//
// Supported methods:
//
//	initialize          — protocol handshake
//	tools/list          — enumerate the 15 tools below
//	tools/call          — invoke one of the tools
//
// Tools exposed:
//
//	lookup_vulnerability(package, ecosystem?, version?)
//	check_secret_pattern(text)
//	get_skill(skill_id, budget?)
//	search_skills(query)
//	scan_secrets(text | file_path, format?)
//	check_dependency(package, version?, ecosystem, format?)
//	check_typosquat(package, ecosystem?)
//	map_compliance_control(skill_id | query, framework?)
//	get_sigma_rule(rule_id | query, category?)
//	version_status()
//	scan_dependencies(file_path, format?)
//	scan_github_actions(file_path, format?)
//	scan_dockerfile(file_path, format?)
//	explain_finding(query)
//	policy_check(file_path, severity_floor?)
//
// The library root is determined by, in order:
//   - --path <dir>
//   - $SKILLS_LIBRARY_PATH
//   - the directory containing the running binary
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kennguy3n/skills-library/cmd/skills-mcp/internal/mcp"
)

func main() {
	libraryPath := flag.String("path", "", "path to the skills-library checkout (default: $SKILLS_LIBRARY_PATH or dir of the binary)")
	allowedRoots := flag.String("allowed-roots", "", "comma-separated absolute directories that file-reading tools (scan_secrets, scan_dependencies, scan_github_actions, scan_dockerfile, policy_check) are permitted to read from. When unset, the server defaults to the current working directory as the only allowed root. Pass --allow-any-path to opt out of the default and accept any path the process can stat (sensitive system directories such as ~/.ssh, ~/.aws, ~/.gnupg and /etc/shadow are always denied regardless).")
	allowAnyPath := flag.Bool("allow-any-path", false, "disable the default-to-cwd allow-list and accept any absolute path the process can stat. Intended for local debugging only; production callers should pass an explicit --allowed-roots list. The sensitive-directory deny-list still applies.")
	flag.Parse()

	root, err := resolveLibraryRoot(*libraryPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	srv, err := mcp.NewServer(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	// Allow-list resolution, in order of precedence:
	//   1. --allowed-roots <dirs>   -> use exactly those.
	//   2. --allow-any-path         -> no restriction (legacy behaviour).
	//   3. (neither)                -> restrict to the current working directory.
	// The CWD default keeps the server fail-safe: a caller who simply
	// invokes `skills-mcp` from a project root cannot ask the server
	// to read /etc/<anything>, files under another user's home, or
	// arbitrary paths on the host. The --allow-any-path escape hatch
	// is preserved so existing local-debug invocations keep working.
	switch {
	case *allowedRoots != "":
		if *allowAnyPath {
			fmt.Fprintln(os.Stderr, "error: --allowed-roots and --allow-any-path are mutually exclusive")
			os.Exit(1)
		}
		roots := strings.Split(*allowedRoots, ",")
		if err := srv.SetAllowedRoots(roots); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case *allowAnyPath:
		// Leave the allow-list empty (no restriction).
	default:
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: resolve cwd for default allow-list:", err)
			os.Exit(1)
		}
		if err := srv.SetAllowedRoots([]string{cwd}); err != nil {
			fmt.Fprintln(os.Stderr, "error: default allow-list:", err)
			os.Exit(1)
		}
	}
	if err := srv.Serve(bufio.NewReader(os.Stdin), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func resolveLibraryRoot(arg string) (string, error) {
	if arg != "" {
		return filepath.Abs(arg)
	}
	if env := os.Getenv("SKILLS_LIBRARY_PATH"); env != "" {
		return filepath.Abs(env)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve binary path: %w", err)
	}
	return filepath.Dir(exe), nil
}
