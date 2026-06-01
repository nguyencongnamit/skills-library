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

// parsePipfileLock reads the Pipfile.lock JSON format produced by
// pipenv. The lockfile has top-level `default` and `develop` maps
// keyed by package name with `{version: "==1.2.3", ...}` entries; we
// emit both groups, tagging each with the originating section in the
// Source field so callers can distinguish runtime from dev deps.
func parsePipfileLock(body []byte) ([]Dependency, error) {
	var doc map[string]map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("pypi: parse Pipfile.lock: %w", err)
	}
	var out []Dependency
	sections := []string{"default", "develop"}
	for _, section := range sections {
		entries, ok := doc[section]
		if !ok {
			continue
		}
		names := make([]string, 0, len(entries))
		for k := range entries {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, name := range names {
			ver := strings.TrimPrefix(entries[name].Version, "==")
			ver = strings.TrimSpace(ver)
			if ver == "" {
				continue
			}
			out = append(out, Dependency{
				Name:      name,
				Version:   ver,
				Ecosystem: "pypi",
				Source:    section + ": " + name,
			})
		}
	}
	return dedupe(out), nil
}

// poetryNameLine and poetryVersionLine match the `name = "..."` and
// `version = "..."` lines inside a `[[package]]` table of poetry.lock.
var (
	poetryNameLine    = regexp.MustCompile(`^name\s*=\s*"([^"]+)"`)
	poetryVersionLine = regexp.MustCompile(`^version\s*=\s*"([^"]+)"`)
)

// parsePoetryLock reads poetry.lock, a TOML file. We do not pull in a
// TOML library — the lockfile shape is tightly constrained and a
// line-oriented scan correctly handles the `[[package]]` tables we
// care about. Each table runs from a `[[package]]` header to the next
// `[` line at column zero; only `name` and `version` are needed for
// the dependency tuple.
func parsePoetryLock(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	inPackage := false
	var name, version string
	flush := func(out *[]Dependency) {
		if inPackage && name != "" && version != "" {
			*out = append(*out, Dependency{
				Name:      name,
				Version:   version,
				Ecosystem: "pypi",
				Source:    name,
			})
		}
		name, version = "", ""
		inPackage = false
	}
	var out []Dependency
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") {
			flush(&out)
			if trimmed == "[[package]]" {
				inPackage = true
			}
			continue
		}
		if !inPackage {
			continue
		}
		if m := poetryNameLine.FindStringSubmatch(line); m != nil {
			name = m[1]
		} else if m := poetryVersionLine.FindStringSubmatch(line); m != nil {
			version = m[1]
		}
	}
	flush(&out)
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("pypi: scan poetry.lock: %w", err)
	}
	return dedupe(out), nil
}

// requirementsLine matches a `name==1.2.3`, `name===1.2.3`, or
// `name @ url` line.  PEP 508 environment markers, hashes, and
// comments are stripped before parsing.
var requirementsLine = regexp.MustCompile(`^([A-Za-z0-9_][A-Za-z0-9_.\-]*)\s*(===?|@)\s*([^\s;]+)`)

// parseRequirementsTxt reads pip's requirements.txt format. Only
// lines with a concrete `==`, `===`, or `@ <url>` pin are emitted —
// loose ranges (`>=1.2`) cannot be turned into an installed version
// without resolving against PyPI, which is out of scope here.
func parseRequirementsTxt(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	var out []Dependency
	for scanner.Scan() {
		raw := scanner.Text()
		// Strip trailing comments and hashes (`--hash=sha256:...`).
		if i := strings.Index(raw, " #"); i >= 0 {
			raw = raw[:i]
		}
		if i := strings.Index(raw, "--hash"); i >= 0 {
			raw = raw[:i]
		}
		// Strip PEP 508 environment markers.
		if i := strings.Index(raw, ";"); i >= 0 {
			raw = raw[:i]
		}
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		m := requirementsLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		ver := strings.TrimSpace(m[3])
		ver = strings.Trim(ver, "\"")
		out = append(out, Dependency{
			Name:      m[1],
			Version:   ver,
			Ecosystem: "pypi",
			Source:    line,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("pypi: scan requirements.txt: %w", err)
	}
	return dedupe(out), nil
}
