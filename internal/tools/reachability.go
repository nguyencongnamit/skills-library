package tools

// reachability.go implements DQ-V.1: DB-guided *import* reachability.
//
// It does NOT do generic SAST or whole-program taint. It answers one
// narrow, high-value question, scoped entirely to the verified DB: of the
// dependencies scan_dependencies already flagged (malicious / typosquat /
// CVE), which are *directly imported* in first-party source, and where?
//
// That triage signal is the thing SCA users ask for first — most flagged
// advisories sit in unreachable transitive deps — and because the work is
// guided by the DB (we resolve reachability only for the packages the DB
// flagged, never the whole dependency graph) it stays cheap and FP-free.
//
// HONESTY (this matches the project's eval discipline): an "imported:
// false" verdict means "no direct import of a module matching this name
// was found in scanned source" — NOT "unreachable" and NOT "safe".
// DQ-H.3 extends this for npm: a flagged package you do not import
// directly but which a package you DO import pulls in is surfaced as
// reachable-via, with the dependency path, by walking the package-lock
// graph. Remaining gaps are documented rather than hidden: (1) transitive
// reachability for non-npm ecosystems (yarn/pnpm expose no usable graph
// here; Cargo/Maven/NuGet/RubyGems have no import analysis at all);
// (2) Python distribution-vs-module name divergence (e.g. the PyYAML
// distribution is imported as `yaml`) can hide a real import. Reachability
// is therefore purely ADDITIVE triage: it annotates findings, it never
// suppresses or downgrades one.

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/namncqualgo/skills-library/internal/tools/parsers"
)

// reachabilityLangs maps each analyzable ecosystem to the source-file
// extensions whose imports we parse. An ecosystem absent from this map is
// reported as "not analyzed" (verdict unknown), never as "not imported".
var reachabilityLangs = map[string]map[string]bool{
	"npm":  {".js": true, ".jsx": true, ".ts": true, ".tsx": true, ".mjs": true, ".cjs": true},
	"pypi": {".py": true, ".pyi": true},
	"go":   {".go": true},
}

// ImportSite is one source location that directly imports a flagged
// package. File is relative to the reachability scan root.
type ImportSite struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// ReachabilityFinding annotates one DB-flagged dependency with whether it
// is directly imported in first-party source. Analyzed is false for
// ecosystems whose imports we don't parse — in which case Imported is not
// meaningful (the verdict is "unknown", not "no").
type ReachabilityFinding struct {
	Package   string       `json:"package"`
	Version   string       `json:"version,omitempty"`
	Ecosystem string       `json:"ecosystem"`
	Severity  string       `json:"severity"`
	Category  string       `json:"category"`
	Analyzed  bool         `json:"analyzed"`
	Imported  bool         `json:"imported"`
	Sites     []ImportSite `json:"sites,omitempty"`
	// TransitiveAnalyzed is true when dependency-graph reachability was
	// computed for this finding (npm only — when a package-lock graph and
	// import roots were both available). TransitiveVia, when non-empty, is the
	// path imported-root → … → this package: it is reachable via a parent you
	// import, even though it is not itself directly imported. (DQ-H.3)
	TransitiveAnalyzed bool     `json:"transitive_analyzed,omitempty"`
	TransitiveVia      []string `json:"transitive_via,omitempty"`
}

// ReachabilityReport is what scan-reachability / check_reachability return.
// The three counts partition Findings (imported + not-imported analyzed +
// not-analyzed), so a CI consumer can branch on "any imported finding".
type ReachabilityReport struct {
	ScanPath         string                `json:"scan_path"`
	Findings         []ReachabilityFinding `json:"findings"`
	ImportedCount    int                   `json:"imported_count"`
	TransitiveCount  int                   `json:"transitive_reachable_count"`
	NotImportedCount int                   `json:"not_imported_count"`
	NotAnalyzedCount int                   `json:"not_analyzed_count"`
}

// importRef is one extracted import: spec is the normalized match key
// (npm package name, Python top-level module, or Go import path).
type importRef struct {
	spec string
	file string
	line int
}

// AnalyzeReachability discovers lockfiles under scanPath, runs
// scan_dependencies to collect the DB-flagged set, then determines which
// flagged packages are directly imported in first-party source beneath
// scanPath. A project with no flagged dependencies returns an empty
// (non-nil) Findings slice — there is nothing to triage.
func (l *Library) AnalyzeReachability(scanPath string) (*ReachabilityReport, error) {
	lockfiles, err := DiscoverLockfiles(scanPath)
	if err != nil {
		return nil, err
	}

	// 1. Collect DB-flagged dependencies, de-duplicated by (ecosystem,
	//    package). The first finding per package wins (its severity is
	//    representative; the import question is per-package, not per-CVE).
	type flagged struct{ pkg, version, ecosystem, severity, category string }
	seen := map[string]flagged{}
	order := []string{}
	for _, lf := range lockfiles {
		res, err := l.ScanDependencies(lf)
		if err != nil {
			continue
		}
		for _, f := range res.Findings {
			if f.Category == "scan-error" {
				continue
			}
			key := strings.ToLower(f.Ecosystem) + "|" + f.Package
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = flagged{f.Package, f.Version, f.Ecosystem, f.Severity, f.Category}
			order = append(order, key)
		}
	}

	report := &ReachabilityReport{ScanPath: scanPath, Findings: []ReachabilityFinding{}}
	if len(seen) == 0 {
		return report, nil
	}

	// 2. Extract imports from first-party source — but only for the
	//    ecosystems that actually have a flagged package, so we never walk
	//    the tree for a language with nothing to find.
	needEco := map[string]bool{}
	for _, fl := range seen {
		needEco[strings.ToLower(fl.ecosystem)] = true
	}
	imports, err := l.extractImports(scanPath, needEco)
	if err != nil {
		return nil, err
	}

	// 2b. Transitive reachability (DQ-H.3, npm only): from the packages
	//     actually imported in source, walk the lockfile dependency graph so a
	//     flagged package that a directly-imported package pulls in is
	//     recognised as reachable-via even when it is not itself imported.
	var npmVia map[string][]string
	npmGraphReady := false
	if needEco["npm"] {
		roots := map[string]bool{}
		for _, r := range imports["npm"] {
			roots[r.spec] = true
		}
		if len(roots) > 0 {
			if graph, ok := l.buildNPMGraph(scanPath); ok {
				rs := make([]string, 0, len(roots))
				for n := range roots {
					rs = append(rs, n)
				}
				npmVia = npmReachableVia(graph, rs)
				npmGraphReady = true
			}
		}
	}

	// 3. Match each flagged package against the extracted imports.
	for _, key := range order {
		fl := seen[key]
		eco := strings.ToLower(fl.ecosystem)
		_, analyzable := reachabilityLangs[eco]
		rf := ReachabilityFinding{
			Package:   fl.pkg,
			Version:   fl.version,
			Ecosystem: fl.ecosystem,
			Severity:  fl.severity,
			Category:  fl.category,
			Analyzed:  analyzable,
		}
		if analyzable {
			if sites := matchImport(eco, fl.pkg, imports[eco]); len(sites) > 0 {
				rf.Imported = true
				rf.Sites = sites
			} else if eco == "npm" && npmGraphReady {
				rf.TransitiveAnalyzed = true
				if path, ok := npmVia[fl.pkg]; ok && len(path) > 1 {
					rf.TransitiveVia = path
				}
			}
		}
		report.Findings = append(report.Findings, rf)
		// Buckets are mutually exclusive so they sum to the finding count:
		// transitive-reachable is its own category, not also counted as
		// not-imported.
		switch {
		case !analyzable:
			report.NotAnalyzedCount++
		case rf.Imported:
			report.ImportedCount++
		case len(rf.TransitiveVia) > 0:
			report.TransitiveCount++
		default:
			report.NotImportedCount++
		}
	}
	return report, nil
}

// buildNPMGraph merges the dependency graphs of every package-lock.json /
// npm-shrinkwrap.json under scanPath into one name -> []name adjacency map.
// Returns (graph, true) only if at least one npm lockfile graph was parsed;
// (nil, false) for a project with no npm lockfile (yarn/pnpm expose no edges,
// so transitive reachability is npm-first by design).
func (l *Library) buildNPMGraph(scanPath string) (map[string][]string, bool) {
	files, err := WalkScanFiles(scanPath, func(p string) bool {
		b := filepath.Base(p)
		return b == "package-lock.json" || b == "npm-shrinkwrap.json"
	})
	if err != nil || len(files) == 0 {
		return nil, false
	}
	merged := map[string]map[string]bool{}
	parsed := false
	for _, f := range files {
		body, _, rerr := l.readScanFile("check_reachability", f)
		if rerr != nil {
			continue
		}
		g, perr := parsers.NPMPackageLockGraph(body)
		if perr != nil {
			continue
		}
		parsed = true
		for from, tos := range g {
			if merged[from] == nil {
				merged[from] = map[string]bool{}
			}
			for _, t := range tos {
				merged[from][t] = true
			}
		}
	}
	if !parsed {
		return nil, false
	}
	out := make(map[string][]string, len(merged))
	for from, tos := range merged {
		lst := make([]string, 0, len(tos))
		for t := range tos {
			lst = append(lst, t)
		}
		sort.Strings(lst)
		out[from] = lst
	}
	return out, true
}

// npmReachableVia does a BFS from the imported-package roots over the
// dependency graph and returns, for each reachable package, the path
// root → … → package (including the package itself). Roots map to a
// single-element path. Deterministic: roots and adjacency are pre-sorted.
func npmReachableVia(graph map[string][]string, roots []string) map[string][]string {
	via := map[string][]string{}
	sort.Strings(roots)
	queue := make([]string, 0, len(roots))
	for _, r := range roots {
		if _, ok := via[r]; !ok {
			via[r] = []string{r}
			queue = append(queue, r)
		}
	}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, dep := range graph[cur] {
			if _, ok := via[dep]; ok {
				continue
			}
			path := make([]string, len(via[cur])+1)
			copy(path, via[cur])
			path[len(path)-1] = dep
			via[dep] = path
			queue = append(queue, dep)
		}
	}
	return via
}

// extractImports walks first-party source under scanPath (WalkScanFiles
// already skips node_modules / vendor / .git and binary/oversized files)
// and returns, per ecosystem, every import reference found. Only the
// extensions belonging to a needed ecosystem are read.
func (l *Library) extractImports(scanPath string, ecos map[string]bool) (map[string][]importRef, error) {
	extEco := map[string]string{}
	for eco := range ecos {
		for ext := range reachabilityLangs[eco] {
			extEco[ext] = eco
		}
	}
	out := map[string][]importRef{}
	if len(extEco) == 0 {
		return out, nil
	}
	files, err := WalkScanFiles(scanPath, func(p string) bool {
		_, ok := extEco[strings.ToLower(filepath.Ext(p))]
		return ok
	})
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		body, _, err := l.readScanFile("check_reachability", f)
		if err != nil {
			continue
		}
		rel, rerr := filepath.Rel(scanPath, f)
		if rerr != nil || rel == "" {
			rel = filepath.Base(f)
		}
		eco := extEco[strings.ToLower(filepath.Ext(f))]
		switch eco {
		case "npm":
			out[eco] = append(out[eco], extractJSImports(string(body), rel)...)
		case "pypi":
			out[eco] = append(out[eco], extractPyImports(string(body), rel)...)
		case "go":
			out[eco] = append(out[eco], extractGoImports(string(body), rel)...)
		}
	}
	return out, nil
}

// matchImport returns the import sites where pkg is directly imported,
// applying ecosystem-specific name matching. Sites are de-duplicated by
// file:line and sorted for deterministic output.
func matchImport(eco, pkg string, refs []importRef) []ImportSite {
	var sites []ImportSite
	seen := map[string]bool{}
	add := func(r importRef) {
		k := r.file + ":" + strconv.Itoa(r.line)
		if seen[k] {
			return
		}
		seen[k] = true
		sites = append(sites, ImportSite{File: r.file, Line: r.line})
	}
	switch eco {
	case "npm":
		for _, r := range refs {
			if r.spec == pkg {
				add(r)
			}
		}
	case "pypi":
		want := normalizePyName(pkg)
		for _, r := range refs {
			if normalizePyName(r.spec) == want {
				add(r)
			}
		}
	case "go":
		for _, r := range refs {
			if r.spec == pkg || strings.HasPrefix(r.spec, pkg+"/") {
				add(r)
			}
		}
	}
	sort.Slice(sites, func(i, j int) bool {
		if sites[i].File != sites[j].File {
			return sites[i].File < sites[j].File
		}
		return sites[i].Line < sites[j].Line
	})
	return sites
}

// --- import extractors (line-aware, regex-based) ---------------------------

var (
	jsFromRe       = regexp.MustCompile(`\bfrom\s*['"]([^'"]+)['"]`)
	jsRequireRe    = regexp.MustCompile(`\brequire\s*\(\s*['"]([^'"]+)['"]`)
	jsDynImportRe  = regexp.MustCompile(`\bimport\s*\(\s*['"]([^'"]+)['"]`)
	jsBareImportRe = regexp.MustCompile(`^\s*import\s+['"]([^'"]+)['"]`)
)

// extractJSImports pulls module specifiers from ES `import`/`export … from`,
// side-effect `import 'x'`, CommonJS `require('x')`, and dynamic
// `import('x')`, mapping each to its package name. Relative ("./x") and
// absolute ("/x") specifiers are dropped.
func extractJSImports(src, file string) []importRef {
	var out []importRef
	for i, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
			continue
		}
		ln := i + 1
		for _, re := range []*regexp.Regexp{jsFromRe, jsRequireRe, jsDynImportRe, jsBareImportRe} {
			for _, m := range re.FindAllStringSubmatch(line, -1) {
				if pkg := jsPackageName(m[1]); pkg != "" {
					out = append(out, importRef{spec: pkg, file: file, line: ln})
				}
			}
		}
	}
	return out
}

// jsPackageName reduces an npm module specifier to its package name:
// "lodash/fp" -> "lodash", "@scope/pkg/sub" -> "@scope/pkg". Relative or
// absolute specifiers (not packages) return "".
func jsPackageName(spec string) string {
	if spec == "" || strings.HasPrefix(spec, ".") || strings.HasPrefix(spec, "/") {
		return ""
	}
	parts := strings.Split(spec, "/")
	if strings.HasPrefix(spec, "@") {
		if len(parts) >= 2 {
			return parts[0] + "/" + parts[1]
		}
		return spec
	}
	return parts[0]
}

var (
	pyFromRe   = regexp.MustCompile(`^\s*from\s+([.\w]+)\s+import\b`)
	pyImportRe = regexp.MustCompile(`^\s*import\s+(.+)$`)
)

// extractPyImports pulls top-level module names from `import a, b.c` and
// `from x.y import z`, dropping relative (`from . import x`) imports and
// trailing `#` comments. The captured name is the first dotted segment.
func extractPyImports(src, file string) []importRef {
	var out []importRef
	for i, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		ln := i + 1
		if m := pyFromRe.FindStringSubmatch(line); m != nil {
			if mod := m[1]; !strings.HasPrefix(mod, ".") {
				if top := strings.SplitN(mod, ".", 2)[0]; top != "" {
					out = append(out, importRef{spec: top, file: file, line: ln})
				}
			}
			continue
		}
		if m := pyImportRe.FindStringSubmatch(line); m != nil {
			rest := m[1]
			if idx := strings.Index(rest, "#"); idx >= 0 {
				rest = rest[:idx]
			}
			for _, part := range strings.Split(rest, ",") {
				name := strings.TrimSpace(part)
				if fields := strings.Fields(name); len(fields) > 0 {
					name = fields[0] // "x as y" -> "x"
				}
				if name == "" || strings.HasPrefix(name, ".") {
					continue
				}
				if top := strings.SplitN(name, ".", 2)[0]; top != "" {
					out = append(out, importRef{spec: top, file: file, line: ln})
				}
			}
		}
	}
	return out
}

// normalizePyName folds a PyPI distribution name and a Python module name
// toward a common key (lowercase, separators stripped) so e.g. the
// "Flask-Cors" distribution matches `import flask_cors`. It cannot bridge
// genuinely different names (PyYAML -> yaml); that gap is documented.
func normalizePyName(s string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(s))
}

var (
	goSingleImportRe = regexp.MustCompile(`^\s*import\s+(?:[\w./]+\s+)?"([^"]+)"`)
	goImportBlockRe  = regexp.MustCompile(`^\s*import\s*\(`)
	goImportPathRe   = regexp.MustCompile(`^\s*(?:[\w._]+\s+)?"([^"]+)"`)
)

// extractGoImports pulls import paths from both single-line imports and
// `import ( … )` blocks, tolerating named/blank/dot aliases.
func extractGoImports(src, file string) []importRef {
	var out []importRef
	inBlock := false
	for i, line := range strings.Split(src, "\n") {
		ln := i + 1
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") {
			continue
		}
		if inBlock {
			if strings.HasPrefix(t, ")") {
				inBlock = false
				continue
			}
			if m := goImportPathRe.FindStringSubmatch(line); m != nil {
				out = append(out, importRef{spec: m[1], file: file, line: ln})
			}
			continue
		}
		if goImportBlockRe.MatchString(line) {
			inBlock = true
			continue
		}
		if m := goSingleImportRe.FindStringSubmatch(line); m != nil {
			out = append(out, importRef{spec: m[1], file: file, line: ln})
		}
	}
	return out
}
