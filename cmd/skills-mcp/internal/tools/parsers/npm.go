package parsers

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// parseNPMPackageLock reads the npm v1, v2, and v3 lockfile shapes.
//
// v1 stores the dependency tree under a recursive `dependencies` map
// keyed by package name. v2 keeps the v1 tree for compatibility and
// adds a flat `packages` map keyed by the install-relative path
// ("node_modules/foo"). v3 drops the legacy `dependencies` tree and
// only emits `packages`. We prefer `packages` when present so we get
// the flat layout — it is what npm itself resolves against.
//
// `npm-shrinkwrap.json` uses the same schema and shares this parser.
func parseNPMPackageLock(body []byte) ([]Dependency, error) {
	var doc struct {
		LockfileVersion int `json:"lockfileVersion"`
		// v2/v3: flat keyed by "node_modules/<name>".
		Packages map[string]struct {
			Version string `json:"version"`
			Dev     bool   `json:"dev,omitempty"`
		} `json:"packages,omitempty"`
		// v1: recursive tree.
		Dependencies map[string]npmV1Entry `json:"dependencies,omitempty"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("npm: parse package-lock.json: %w", err)
	}
	var out []Dependency
	if len(doc.Packages) > 0 {
		// Sort keys so the output is deterministic across runs.
		keys := make([]string, 0, len(doc.Packages))
		for k := range doc.Packages {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				// Root entry — describes the project itself, not a dep.
				continue
			}
			name := strings.TrimPrefix(k, "node_modules/")
			if i := strings.LastIndex(name, "/node_modules/"); i >= 0 {
				name = name[i+len("/node_modules/"):]
			}
			ver := doc.Packages[k].Version
			if name == "" || ver == "" {
				continue
			}
			out = append(out, Dependency{
				Name:      name,
				Version:   ver,
				Ecosystem: "npm",
				Source:    k,
			})
		}
		return dedupe(out), nil
	}
	flattenNPMv1(doc.Dependencies, "", &out)
	return dedupe(out), nil
}

type npmV1Entry struct {
	Version      string                `json:"version"`
	Dependencies map[string]npmV1Entry `json:"dependencies,omitempty"`
}

func flattenNPMv1(deps map[string]npmV1Entry, prefix string, out *[]Dependency) {
	if len(deps) == 0 {
		return
	}
	keys := make([]string, 0, len(deps))
	for k := range deps {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, name := range keys {
		entry := deps[name]
		if entry.Version != "" {
			src := name
			if prefix != "" {
				src = prefix + " > " + name
			}
			*out = append(*out, Dependency{
				Name:      name,
				Version:   entry.Version,
				Ecosystem: "npm",
				Source:    src,
			})
		}
		nested := name
		if prefix != "" {
			nested = prefix + " > " + name
		}
		flattenNPMv1(entry.Dependencies, nested, out)
	}
}

// yarnEntryHeader matches the package descriptor line of a Yarn 1
// lockfile entry. The format is one or more comma-separated
// `<name>@<range>` patterns terminated by a colon. The name itself
// may contain a `@` when it is scoped (`@scope/pkg@1.x`); we handle
// both shapes.
var yarnEntryHeader = regexp.MustCompile(`^("?)((@[^"@,\s]+/)?[^"@,\s]+)@`)

// parseYarnLock reads the Yarn 1 lockfile format. Yarn 2+ ("Berry")
// emits an extended YAML-flavoured form by default but still falls
// back to this format under `nodeLinker: node-modules`; both shapes
// share the `version "<ver>"` line so the regex below catches them.
func parseYarnLock(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	// Yarn entries can be long; bump the line cap to 1 MB.
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	var (
		current string
		out     []Dependency
	)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// An entry header is not indented and ends in ":".
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(line, ":") {
			m := yarnEntryHeader.FindStringSubmatch(trimmed)
			if m == nil {
				current = ""
				continue
			}
			current = m[2]
			continue
		}
		if current == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "version ") || strings.HasPrefix(trimmed, "version:") {
			rest := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(trimmed, "version"), ":"))
			rest = strings.TrimSpace(rest)
			rest = strings.Trim(rest, "\"")
			if rest != "" {
				out = append(out, Dependency{
					Name:      current,
					Version:   rest,
					Ecosystem: "npm",
					Source:    current,
				})
			}
			current = ""
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("npm: scan yarn.lock: %w", err)
	}
	return dedupe(out), nil
}

// pnpmPackagePath matches the `/<name>@<version>` key shape used by
// pnpm-lock.yaml under the `packages:` top-level. Scoped names retain
// their leading `@`.
var pnpmPackagePath = regexp.MustCompile(`^[\s]+/((@[^@/\s]+/)?[^@/\s]+)@([^\s:]+):`)

// parsePnpmLock reads pnpm-lock.yaml without a full YAML decoder.
//
// pnpm's lockfile schema is verbose and version-stamped; the only
// fields we need for scan_dependencies are the `/<name>@<version>:`
// keys under `packages:`. Walking the file line-by-line keeps the
// parser hermetic (no third-party YAML library) and is robust to the
// half-dozen incompatible schema versions pnpm has shipped.
func parsePnpmLock(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	inPackages := false
	var out []Dependency
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "packages:") {
			inPackages = true
			continue
		}
		if inPackages && !strings.HasPrefix(line, " ") && strings.TrimSpace(line) != "" {
			// Left the packages: block.
			inPackages = false
		}
		if !inPackages {
			continue
		}
		m := pnpmPackagePath.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out = append(out, Dependency{
			Name:      m[1],
			Version:   m[3],
			Ecosystem: "npm",
			Source:    strings.TrimSpace(line),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("npm: scan pnpm-lock.yaml: %w", err)
	}
	return dedupe(out), nil
}
