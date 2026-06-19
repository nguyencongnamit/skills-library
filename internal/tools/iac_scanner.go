package tools

// iac_scanner.go is the Infrastructure-as-Code hardening scanner (DQ-H.2):
// a line-oriented pass over Terraform (.tf), Kubernetes manifests, and AWS
// CloudFormation templates that surfaces the high-signal misconfigurations
// the iac-security / container-security checklists describe.
//
// Why Go-side inline rules (like ScanDockerfile) rather than the checklist
// YAML: the patterns reach into concrete IaC syntax (HCL `cidr_blocks`,
// k8s `securityContext`, CFN `Resources`) that the hardening checklists
// deliberately keep human-readable. The rule IDs match the checklist IDs
// (skills/iac-security/checklists/*.yaml, skills/container-security/
// checklists/k8s_pod_security.yaml) so a consumer can join the two surfaces,
// and every ID is CWE-tagged in rule_cwe.go so a finding feeds the CF.7
// cross-framework spine.
//
// Detection is intentionally conservative — every rule fires only on an
// explicit bad value (e.g. `privileged: true`, `runAsUser: 0`,
// `cidr_blocks = ["0.0.0.0/0"]`), never on the ABSENCE of a hardening
// setting. Absence-based checklist items (state locking, default-deny
// NetworkPolicy, deletion protection, …) are out of scope for a single-file
// regex scanner and stay in the human checklist. This keeps the false
// positive rate near zero, which is the eval-wall contract for a new check.

import (
	"path/filepath"
	"regexp"
	"strings"
)

// IaCKind classifies which IaC dialect a scanned file is, so a finding can
// be attributed to the right checklist and the right rule family.
type IaCKind string

const (
	IaCTerraform      IaCKind = "terraform"
	IaCKubernetes     IaCKind = "kubernetes"
	IaCCloudFormation IaCKind = "cloudformation"
)

// IaCFinding mirrors DockerfileFinding so the report, gate, and SARIF
// surfaces can render it through the same line-based shape.
type IaCFinding struct {
	RuleID     string  `json:"rule_id"`
	Severity   string  `json:"severity"`
	Confidence string  `json:"confidence,omitempty"`
	Kind       IaCKind `json:"kind"`
	Title      string  `json:"title"`
	Fix        string  `json:"fix,omitempty"`
	Line       int     `json:"line"`
	Snippet    string  `json:"snippet"`
}

// ScanIaCResult is what scan_iac returns. Kind is the detected dialect, or
// "" when the file was not recognised as IaC (in which case Findings is
// empty — scan_iac is safe to call on any file).
type ScanIaCResult struct {
	FilePath string       `json:"file_path"`
	FileSize int64        `json:"file_size"`
	Kind     IaCKind      `json:"kind,omitempty"`
	Findings []IaCFinding `json:"findings"`
}

// iacCheck is one inline line-oriented rule. The pattern sees a single
// (comment-stripped) line at a time, which keeps both the regex and the
// reported line number simple.
type iacCheck struct {
	id       string
	severity string
	title    string
	fix      string
	pattern  *regexp.Regexp
}

// terraformChecks fire on explicit insecure HCL. Each ID matches a pattern
// in skills/iac-security/checklists/terraform_hardening.yaml.
var terraformChecks = []iacCheck{
	{
		id:       "tf-no-hardcoded-creds",
		severity: "critical",
		title:    "Provider/resource credential is hard-coded as a literal",
		fix:      "Source credentials from environment, OIDC, or an assume-role block — never inline a literal key.",
		// A credential key assigned a quoted literal that contains no
		// interpolation ($ excluded). 6+ chars rules out empty / trivial
		// placeholders.
		pattern: regexp.MustCompile(`(?i)^\s*(access_key|secret_key|secret_access_key|password|client_secret|private_key)\s*=\s*"[^"$]{6,}"`),
	},
	{
		id:       "tf-iam-no-wildcard",
		severity: "critical",
		title:    "IAM policy grants Action=\"*\" (full wildcard)",
		fix:      "Replace the wildcard with a concrete list of actions the principal needs.",
		// `actions = ["*"]` (HCL) or `"Action": "*"` (JSON policy doc).
		// A service-scoped wildcard like "s3:*" is deliberately NOT matched.
		pattern: regexp.MustCompile(`(?i)"?actions?"?\s*[:=]\s*\[?\s*"\*"`),
	},
	{
		id:       "tf-security-group-no-world-admin",
		severity: "high",
		title:    "Security group opens ingress to 0.0.0.0/0",
		fix:      "Restrict cidr_blocks to known networks; never expose admin/database ports (22/3389/3306/5432/…) to the world.",
		pattern:  regexp.MustCompile(`(?i)(cidr_blocks?|cidr_ipv?4?)\s*=.*0\.0\.0\.0/0`),
	},
	{
		id:       "tf-rds-not-public",
		severity: "high",
		title:    "Database instance is publicly accessible",
		fix:      "Set publicly_accessible = false unless an internet-facing design is explicitly documented.",
		pattern:  regexp.MustCompile(`(?i)publicly_accessible\s*=\s*true\b`),
	},
	{
		id:       "tf-no-skip-tls",
		severity: "critical",
		title:    "Provider disables TLS verification",
		fix:      "Remove insecure=true / skip_tls_verify=true; validate certificates against a trusted CA.",
		pattern:  regexp.MustCompile(`(?i)(insecure|skip_tls_verify)\s*=\s*true\b`),
	},
	{
		id:       "tf-storage-encrypted",
		severity: "high",
		title:    "Storage encryption is explicitly disabled",
		fix:      "Set encrypted/storage_encrypted = true and supply a KMS/CMEK key.",
		pattern:  regexp.MustCompile(`(?i)(storage_encrypted|encrypted)\s*=\s*false\b`),
	},
}

// cloudformationChecks fire on explicit insecure CloudFormation. The
// hardcoded-secret rule is the highest-signal, lowest-FP CFN check; absence
// rules (deletion protection, NoEcho) stay in the human checklist.
var cloudformationChecks = []iacCheck{
	{
		id:       "cfn-dynamic-references",
		severity: "critical",
		title:    "Secret is a literal in the template (no dynamic reference)",
		fix:      "Use {{resolve:secretsmanager:...}} / {{resolve:ssm-secure:...}} or AWS::SecretsManager::Secret — never a literal password.",
		// A *Password key assigned a literal scalar that is NOT a
		// dynamic-reference ({{resolve), an intrinsic (!Ref / !Sub /
		// Fn::), or a parameter. The negative lookahead-free form keeps
		// it RE2-safe: we match a quoted-or-bare literal that contains
		// none of { ! } characters.
		pattern: regexp.MustCompile(`(?i)^\s*"?\w*password"?\s*:\s*['"]?[^'"{}!\s][^'"{}!]{4,}['"]?\s*$`),
	},
}

// kubernetesChecks fire on explicit insecure pod/container security context.
// Each ID matches skills/container-security/checklists/k8s_pod_security.yaml.
// The capabilities rule (k8s-drop-all-capabilities) needs add/drop context
// and is handled separately by k8sCapabilityFindings.
var kubernetesChecks = []iacCheck{
	{
		id:       "k8s-no-privileged",
		severity: "critical",
		title:    "Container runs privileged or allows privilege escalation",
		fix:      "Set privileged: false and allowPrivilegeEscalation: false.",
		pattern:  regexp.MustCompile(`(?i)^\s*(privileged|allowPrivilegeEscalation)\s*:\s*true\b`),
	},
	{
		id:       "k8s-run-as-non-root",
		severity: "critical",
		title:    "Container may run as root (runAsNonRoot:false or runAsUser:0)",
		fix:      "Set runAsNonRoot: true and runAsUser to a high non-zero UID (>= 10000).",
		pattern:  regexp.MustCompile(`(?i)^\s*(runAsNonRoot\s*:\s*false|runAsUser\s*:\s*0)\b`),
	},
	{
		id:       "k8s-no-host-namespaces",
		severity: "critical",
		title:    "Pod shares a host namespace (hostNetwork/hostPID/hostIPC)",
		fix:      "Remove hostNetwork/hostPID/hostIPC or set them to false — host namespaces break pod isolation.",
		pattern:  regexp.MustCompile(`(?i)^\s*host(Network|PID|IPC)\s*:\s*true\b`),
	},
	{
		id:       "k8s-no-host-paths",
		severity: "critical",
		title:    "Pod mounts a hostPath volume",
		fix:      "Replace hostPath with a managed volume (emptyDir, PVC, configMap); hostPath exposes the node filesystem.",
		pattern:  regexp.MustCompile(`(?i)^\s*hostPath\s*:`),
	},
}

// dangerousCaps are Linux capabilities that must not be added back after a
// drop-all; SYS_ADMIN in particular is close to full root.
var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "NET_RAW": true,
	"SYS_PTRACE": true, "SYS_MODULE": true, "DAC_OVERRIDE": true, "SETUID": true,
}

// iacCandidateExts are the file extensions scan_iac will consider. The
// classifier then sniffs the content, so a non-IaC .yaml/.json simply
// returns no findings.
var iacCandidateExts = map[string]bool{
	".tf": true, ".yaml": true, ".yml": true, ".json": true, ".template": true,
}

// IsIaCCandidate reports whether path has an extension scan_iac inspects.
// Used by the directory walkers (evidence --scan) to narrow the file set
// before the content sniff in ScanIaC decides whether it is really IaC.
func IsIaCCandidate(path string) bool {
	if strings.HasSuffix(strings.ToLower(path), ".tf.json") {
		return true
	}
	return iacCandidateExts[strings.ToLower(filepath.Ext(path))]
}

var (
	reTerraformBlock = regexp.MustCompile(`(?m)^\s*(resource|provider|module|variable|terraform|data|output)\s+"`)
	reK8sAPIVersion  = regexp.MustCompile(`(?m)^\s*apiVersion\s*:`)
	reK8sKind        = regexp.MustCompile(`(?m)^\s*kind\s*:`)
	reCFNResources   = regexp.MustCompile(`(?m)^\s*"?Resources"?\s*:`)
)

// classifyIaC sniffs which IaC dialect body is, or "" when unrecognised.
// Extension is authoritative for Terraform (.tf / .tf.json); YAML/JSON is
// disambiguated by content because k8s and CloudFormation share extensions.
func classifyIaC(path string, body []byte) IaCKind {
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".tf") || strings.HasSuffix(lower, ".tf.json") {
		return IaCTerraform
	}
	text := string(body)
	// Kubernetes manifests carry both apiVersion and kind at the document
	// root — a strong, low-FP signal that also excludes CFN and CI YAML.
	if reK8sAPIVersion.MatchString(text) && reK8sKind.MatchString(text) {
		return IaCKubernetes
	}
	// CloudFormation: the format-version key, or a Resources map with at
	// least one AWS:: typed resource.
	if strings.Contains(text, "AWSTemplateFormatVersion") ||
		(reCFNResources.MatchString(text) && strings.Contains(text, "AWS::")) {
		return IaCCloudFormation
	}
	// A bare .tf-less HCL file with terraform blocks (rare; e.g. piped
	// stdin). Checked last so YAML never misclassifies as Terraform.
	if reTerraformBlock.MatchString(text) {
		return IaCTerraform
	}
	return ""
}

// ScanIaC classifies filePath and runs the matching rule family. A file
// that is not recognised IaC returns an empty (Kind: "") result rather than
// an error, so the directory walkers can hand it any candidate file.
func (l *Library) ScanIaC(filePath string) (*ScanIaCResult, error) {
	const op = "scan_iac"
	body, size, err := l.readScanFile(op, filePath)
	if err != nil {
		return nil, err
	}
	out := &ScanIaCResult{FilePath: filePath, FileSize: size, Findings: []IaCFinding{}}
	kind := classifyIaC(filePath, body)
	if kind == "" {
		return out, nil
	}
	out.Kind = kind

	var family []iacCheck
	switch kind {
	case IaCTerraform:
		family = terraformChecks
	case IaCCloudFormation:
		family = cloudformationChecks
	case IaCKubernetes:
		family = kubernetesChecks
	}

	lines := strings.Split(string(body), "\n")
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		for _, c := range family {
			if !c.pattern.MatchString(line) {
				continue
			}
			out.Findings = append(out.Findings, IaCFinding{
				RuleID:     c.id,
				Severity:   c.severity,
				Confidence: "high",
				Kind:       kind,
				Title:      c.title,
				Fix:        c.fix,
				Line:       i + 1,
				Snippet:    truncateSnippet(trimmed, 240),
			})
		}
	}

	if kind == IaCKubernetes {
		out.Findings = append(out.Findings, k8sCapabilityFindings(lines)...)
	}
	return out, nil
}

var (
	reCapAddKey    = regexp.MustCompile(`(?i)^(\s*)add\s*:\s*(\[.*\])?\s*$`)
	reCapDropKey   = regexp.MustCompile(`(?i)^(\s*)drop\s*:`)
	reCapInlineArr = regexp.MustCompile(`(?i)add\s*:\s*\[(.*)\]`)
	reCapListItem  = regexp.MustCompile(`^(\s*)-\s*["']?([A-Za-z_]+)["']?\s*$`)
	reYAMLKey      = regexp.MustCompile(`^(\s*)\S`)
)

// k8sCapabilityFindings detects dangerous Linux capabilities being ADDED
// back (securityContext.capabilities.add). It is context-aware so the
// recommended `drop: [ALL]` is never flagged — only caps under an `add:`
// key. Both the inline-array (`add: ["SYS_ADMIN"]`) and block-list forms
// are handled.
func k8sCapabilityFindings(lines []string) []IaCFinding {
	var out []IaCFinding
	inAdd := false
	addIndent := -1
	emit := func(i int, cap, snippet string) {
		out = append(out, IaCFinding{
			RuleID:     "k8s-drop-all-capabilities",
			Severity:   "high",
			Confidence: "high",
			Kind:       IaCKubernetes,
			Title:      "Dangerous Linux capability added back (" + cap + ")",
			Fix:        "Drop ALL capabilities and add back only the minimal set (e.g. NET_BIND_SERVICE); never add " + cap + ".",
			Line:       i + 1,
			Snippet:    truncateSnippet(strings.TrimSpace(snippet), 240),
		})
	}
	for i, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		// Inline form: `add: ["SYS_ADMIN", "NET_ADMIN"]` on one line.
		if m := reCapInlineArr.FindStringSubmatch(line); m != nil {
			for _, tok := range splitCapList(m[1]) {
				if dangerousCaps[strings.ToUpper(tok)] {
					emit(i, strings.ToUpper(tok), line)
				}
			}
			// An inline add: closes the block context immediately.
			inAdd = false
			addIndent = -1
			continue
		}
		// Block form: an `add:` key opens an add-context until we dedent.
		if m := reCapAddKey.FindStringSubmatch(line); m != nil {
			inAdd = true
			addIndent = len(m[1])
			continue
		}
		if reCapDropKey.MatchString(line) {
			inAdd = false
			addIndent = -1
			continue
		}
		if !inAdd {
			continue
		}
		// While in an add-context, list items more indented than the
		// `add:` key are the added capabilities.
		if m := reCapListItem.FindStringSubmatch(line); m != nil {
			if len(m[1]) <= addIndent {
				inAdd = false
				addIndent = -1
				continue
			}
			if dangerousCaps[strings.ToUpper(m[2])] {
				emit(i, strings.ToUpper(m[2]), line)
			}
			continue
		}
		// Any other key at or below the add indent closes the context.
		if km := reYAMLKey.FindStringSubmatch(line); km != nil && len(km[1]) <= addIndent {
			inAdd = false
			addIndent = -1
		}
	}
	return out
}

// splitCapList splits the inside of an inline YAML flow array into bare
// capability tokens, stripping quotes and whitespace.
func splitCapList(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"'`)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
