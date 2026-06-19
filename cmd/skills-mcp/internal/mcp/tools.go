package mcp

// toolDefinitions returns the MCP tool descriptors served on tools/list.
// The schemas follow the MCP `tools/list` definition: name, description,
// and an inputSchema JSON-Schema-shaped object describing the arguments.
func toolDefinitions() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "lookup_vulnerability",
			"description": "Look up a package in the Skills Library supply-chain vulnerability database. Returns malicious package entries and known typosquats that match the package name.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name to look up."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "One of npm, pypi, crates, go, rubygems, maven, nuget, github-actions, docker. Optional — defaults to all ecosystems.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
					"version": map[string]string{"type": "string", "description": "Optional version pin. Empty matches all affected versions."},
				},
				"required": []string{"package"},
			},
		},
		{
			"name":        "check_secret_pattern",
			"description": "Run the Skills Library secret-detection rules against the supplied text and return matches with severity, name, and whether the match is a known false positive.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"text": map[string]string{"type": "string", "description": "Text to scan for secrets."},
				},
				"required": []string{"text"},
			},
		},
		{
			"name":        "get_skill",
			"description": "Return the requested tier of a Skills Library skill (minimal, compact, or full).",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"skill_id": map[string]string{"type": "string", "description": "Skill ID, e.g. 'secret-detection'."},
					"budget":   map[string]string{"type": "string", "description": "One of minimal, compact, full. Default: compact."},
				},
				"required": []string{"skill_id"},
			},
		},
		{
			"name":        "search_skills",
			"description": "Search the Skills Library by substring match against title, description, ID, and category. Returns matching skill metadata.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]string{"type": "string", "description": "Substring query."},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "scan_secrets",
			"description": "Scan text or a local file for secrets and DLP patterns using the Skills Library secret-detection rules. Pass `text` for inline content or `file_path` for an absolute path on the host running the MCP server. When --allowed-roots is configured at startup, `file_path` must resolve to a location under one of those roots; sensitive system directories (~/.ssh, ~/.aws, ~/.gnupg, /etc/shadow, ...) are always denied. Pass `format`=\"sarif\" to receive a SARIF 2.1.0 log instead of the rich JSON shape. Returns structured matches with severity, location, score, entropy, and whether the match is a known false positive.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"text":      map[string]string{"type": "string", "description": "Inline text to scan. Mutually exclusive with file_path."},
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a local file to scan. Files larger than 10 MiB are rejected. Subject to --allowed-roots and the sensitive-directory deny-list."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log for CI consumption.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
			},
		},
		{
			"name":        "check_dependency",
			"description": "Check a package name (and optional version) against the malicious-packages database for one ecosystem. Returns malicious matches, typosquat matches, and any CVE patterns that mention the package. Version matching is semver-aware: ranges like \"all\", \"*\", \"pre-X.Y.Z\", \">=X.Y.Z\", \"<X.Y.Z\", and inclusive \"X.Y.Z - A.B.C\" are evaluated against the supplied version. Pass `format`=\"sarif\" to receive a SARIF 2.1.0 log instead of the rich JSON shape. Use this when an LLM is about to import or install a new dependency.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name."},
					"version": map[string]string{"type": "string", "description": "Optional version pin. Empty matches all affected versions."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "Package ecosystem.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log for CI consumption.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"package", "ecosystem"},
			},
		},
		{
			"name":        "check_typosquat",
			"description": "Check a package name against the known typosquat database. Returns every typosquat entry where the supplied name appears as the target (legitimate package being squatted) or as a known typosquat. Useful for catching dependency-confusion attempts before the install lands.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"package": map[string]string{"type": "string", "description": "Package name to check."},
					"ecosystem": map[string]interface{}{
						"type":        "string",
						"description": "Optional ecosystem filter.",
						"enum":        []string{"npm", "pypi", "crates", "go", "rubygems", "maven", "nuget", "github-actions", "docker"},
					},
				},
				"required": []string{"package"},
			},
		},
		{
			"name":        "map_compliance_control",
			"description": "Map a Skills Library skill ID, category, or free-text term to the compliance controls that cover it across SOC 2, HIPAA, PCI DSS, NIST SSDF, OWASP ASVS, SLSA, EU CRA, NIST AI RMF, and the EU AI Act. Returns the matching controls grouped by framework, each carrying its mapped automated checks and CWE identifiers (schema 2.0) so an LLM can cite the right control alongside a fix. Pass `path` to additionally RUN each matched control's checks over that codebase and get a live pass/fail (verification) per control.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"skill_id": map[string]string{"type": "string", "description": "A Skills Library skill ID (e.g. 'secret-detection'). Either skill_id or query is required."},
					"query":    map[string]string{"type": "string", "description": "Free-text query matched case-insensitively against control title and description."},
					"framework": map[string]interface{}{
						"type":        "string",
						"description": "Optional framework filter.",
						"enum":        []string{"soc2", "hipaa", "pci-dss", "nist-ssdf", "owasp-asvs", "slsa", "eu-cra", "nist-ai-rmf", "eu-ai-act"},
					},
					"path": map[string]string{"type": "string", "description": "Optional path to a codebase directory. When set, each matched control's mapped checks are executed against it and the response includes a per-control verification verdict (verified | findings | not_verifiable | error) plus per-check results."},
				},
			},
		},
		{
			"name":        "map_cwe",
			"description": "Resolve a CWE identifier to its cross-framework spine: every compliance control that cites it (grouped by framework), the prevention skills that advise on those controls, the runnable checks that detect or verify it, and the Sigma detection rules that catch its exploitation at runtime. Use this to turn one finding's CWE into the full control → skill → check → detection chain — e.g. given CWE-798 from a secret scan, surface which SOC 2 / PCI / SLSA controls it implicates, which checks prove remediation, and which runtime detections would fire.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"cwe": map[string]string{"type": "string", "description": "A CWE identifier, canonical or bare-number (e.g. 'CWE-798' or '798'). Required."},
				},
				"required": []string{"cwe"},
			},
		},
		{
			"name":        "get_sigma_rule",
			"description": "Return one or more Sigma-format detection rules from the rules/ directory. Either pass `rule_id` for an exact match or `query` for a substring search against title / id / tags. Optionally filter by `category` (cloud, container, endpoint, saas).",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"rule_id": map[string]string{"type": "string", "description": "Exact Sigma rule UUID."},
					"query":   map[string]string{"type": "string", "description": "Substring search against title, id, and tags."},
					"category": map[string]interface{}{
						"type":        "string",
						"description": "Optional category filter (top-level rules/ subdir).",
						"enum":        []string{"cloud", "container", "endpoint", "saas"},
					},
				},
			},
		},
		{
			"name":        "version_status",
			"description": "Return the Skills Library data version, release timestamp, signature status, and a summary of how many files are tracked in the root manifest. Use this before relying on results from the other tools so the LLM can disclose data freshness and trust state.",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "scan_dependencies",
			"description": "Parse a project lockfile or manifest at file_path and run every dependency against the malicious-packages database, the typosquat database, and the CVE-pattern list. Recognises package-lock.json, npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, requirements.txt, Pipfile.lock, poetry.lock, go.sum, Cargo.lock, pom.xml, gradle.lockfile / build.gradle.lockfile, packages.lock.json, *.csproj / *.fsproj / *.vbproj, and Gemfile.lock. Subject to --allowed-roots and the sensitive-directory deny-list. Pass `format`=\"sarif\" for SARIF 2.1.0 output suitable for GitHub Advanced Security ingest.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a lockfile on the host running the MCP server."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			"name":        "scan_github_actions",
			"description": "Run the cicd-security hardening checklist against a `.github/workflows/*.yml` (or .yaml) file. Detects unpinned actions, missing `permissions:` defaults, `pull_request_target` checking out untrusted code, untrusted-input script injection, `curl | sh` patterns, and stored cloud credentials. Subject to --allowed-roots and the sensitive-directory deny-list. Pass `format`=\"sarif\" for SARIF 2.1.0 output.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a GitHub Actions workflow YAML file."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			"name":        "scan_dockerfile",
			"description": "Run a hardening pass over a Dockerfile. Detects untagged or :latest base images, USER root, secrets baked into ENV/ARG, ADD from a remote URL, `curl | sh` install patterns, and apt-get install lines without version pins. Subject to --allowed-roots and the sensitive-directory deny-list. Pass `format`=\"sarif\" for SARIF 2.1.0 output.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a Dockerfile."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			"name":        "scan_iac",
			"description": "Run a hardening pass over an Infrastructure-as-Code file — Terraform (.tf), a Kubernetes manifest, or an AWS CloudFormation template (the dialect is auto-detected from path and content). Detects 0.0.0.0/0 ingress, hard-coded provider/resource credentials, IAM `Action=\"*\"` wildcards, publicly-accessible databases, disabled TLS/encryption, privileged or run-as-root containers, host-namespace/hostPath escapes, and dangerous added Linux capabilities. A file that is not recognised IaC returns no findings. Subject to --allowed-roots and the sensitive-directory deny-list. Pass `format`=\"sarif\" for SARIF 2.1.0 output.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path": map[string]string{"type": "string", "description": "Absolute path to a Terraform, Kubernetes, or CloudFormation file."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"file_path"},
			},
		},
		{
			"name":        "generate_sbom",
			"description": "Generate a CycloneDX 1.5 software bill of materials (SBOM) for a project directory by discovering and parsing its dependency lockfiles (npm, PyPI, Go, Cargo, Maven, NuGet, RubyGems). Returns the standard CycloneDX JSON document: a deterministic, network-free inventory of every resolved (name, version) component, each with a Package URL (purl). The component set is exactly what scan_dependencies evaluates, so the BOM never drifts from the scanner. This is the real artifact the EU CRA Annex I (2)(1) \"draw up a software bill of materials\" obligation asks for. Subject to --allowed-roots and the sensitive-directory deny-list.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]string{"type": "string", "description": "Absolute path to the project directory to inventory. Every recognised lockfile beneath it is discovered and parsed."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "scan_cve_patterns",
			"description": "Scan first-party source for the curated code patterns of known CVEs (e.g. Log4Shell ${jndi:...}, Shellshock, Spring4Shell), language-scoped: each CVE's code_patterns run only against files in the languages it declares. DB-guided source-level reachability, NOT generic SAST — only the hand-tuned regexes shipped in the verified CVE DB run. ADVISORY: a match means a pattern associated with that CVE is present (verify exploitability); it is not wired into the build-failing gate. Patterns that can't compile under RE2 are skipped and counted. Pass format=\"sarif\" for SARIF 2.1.0. Subject to --allowed-roots and the sensitive-directory deny-list.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]string{"type": "string", "description": "Absolute path to the project directory whose source tree is scanned."},
					"format": map[string]interface{}{
						"type":        "string",
						"description": "Output format. Empty (or \"json\") returns the native MCP shape; \"sarif\" returns a SARIF 2.1.0 log.",
						"enum":        []string{"", "json", "sarif"},
					},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "check_reachability",
			"description": "DB-guided import reachability: of the dependencies scan_dependencies already flagged (malicious / typosquat / CVE) in a project's lockfiles, report which are DIRECTLY IMPORTED in first-party source (JavaScript/TypeScript, Python, Go) and at which file:line. For npm it also resolves TRANSITIVE reachability — a flagged package you don't import directly but which an imported package pulls in is reported as reachable-via with its dependency path (DQ-H.3), by walking the package-lock graph. This is targeted triage scoped to the verified DB, NOT generic SAST — reachability is resolved only for flagged packages. Honest limits: \"imported: false\" means no direct import of that name was found, NOT unreachable/safe (transitive reachability for non-npm ecosystems, and Python distribution-vs-module name divergence like PyYAML->yaml, are out of scope); it is additive triage and never suppresses a finding. Ecosystems without import analysis (Cargo, Maven, NuGet, RubyGems) are reported as not-analyzed. Subject to --allowed-roots and the sensitive-directory deny-list.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]string{"type": "string", "description": "Absolute path to the project directory. Lockfiles beneath it are scanned and its source tree is searched for imports of the flagged packages."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "deep_scan",
			"description": "Reachability-prioritized dependency triage: run scan_dependencies, DQ-V.1 import reachability, and DQ-V.2 CVE code-pattern reachability over a project and merge them into ONE ranked list answering 'what should I look at first?'. P1 (reachable) = a flagged package you directly import OR a CVE code pattern present in your source; P2 (transitive/present) = a flagged package you don't import directly but which an imported package pulls in (npm — shown with the dependency path) or one in a non-analyzable ecosystem; P3 (unreachable) = a flagged package the npm dependency graph shows no import path to (likely unused/dev-only). Within a tier, sorted by severity. Composes advisory legs; not gate-wired. Subject to --allowed-roots and the sensitive-directory deny-list.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"path": map[string]string{"type": "string", "description": "Absolute path to the project directory to triage (lockfiles + source tree)."},
				},
				"required": []string{"path"},
			},
		},
		{
			"name":        "list_external_tools",
			"description": "List the industry-standard external CLIs that secure-code skills recommend (declared in each skill's `external_tools` frontmatter), each marked with whether its binary is installed on the current host's PATH. Discovery only — the server never runs these tools. Use it to decide which external scanner to run, then run the chosen one yourself via the shell (e.g. `gitleaks dir` for whole-repo/git-history secret scanning, `hadolint <file>` for Dockerfile linting). The built-in MCP scanners (scan_secrets, scan_dockerfile, …) remain the offline default.",
			"inputSchema": map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			"name":        "explain_finding",
			"description": "Map a CWE ID, CVE ID, or free-text finding description to the relevant Skills Library skills and CVE-pattern entries. Returns the matching skills (with id, title, category, severity, and a short excerpt of the body) plus any CVE rows whose name or description mentions the query. Use this to attach remediation guidance to a SAST / SCA finding from another scanner.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query": map[string]string{"type": "string", "description": "Free-text query — a CWE ID like \"CWE-77\", a CVE ID like \"CVE-2024-12345\", or a finding description."},
				},
				"required": []string{"query"},
			},
		},
		{
			"name":        "gate",
			"description": "Pick the right scanner for file_path and report a CI-friendly pass/fail with a per-severity count. Dispatches to scan_dependencies for lockfiles, scan_github_actions for `.github/workflows/*.{yml,yaml}` files, scan_dockerfile for Dockerfiles, and scan_iac for Terraform (`.tf`) files, falling back to scan_secrets for any other file. Findings at or above `severity_floor` (default: high) fail the check; the response includes `pass` and `exit_code` (0 on pass, 1 on fail) so a CI wrapper can branch on it. (Formerly `policy_check`; that name is still accepted.)",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"file_path":      map[string]string{"type": "string", "description": "Absolute path to the artifact to scan."},
					"severity_floor": map[string]interface{}{"type": "string", "description": "Findings at or above this severity fail the check. Default: high.", "enum": []string{"", "critical", "high", "medium", "low", "info"}},
				},
				"required": []string{"file_path"},
			},
		},
	}
}
