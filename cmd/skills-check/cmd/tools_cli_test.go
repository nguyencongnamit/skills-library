package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repoRootForTest walks up from CWD until it finds go.mod, mirroring
// the helper in internal/tools/library_test.go. Saves every test from
// re-implementing the same walk.
func repoRootForTest(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for dir := wd; dir != "/"; dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
	}
	t.Fatalf("could not find go.mod from %s", wd)
	return ""
}

// TestResolveLibraryRoot locks in the precedence that lets the file
// scanners run inside an arbitrary project: explicit --path wins, then
// $SKILLS_LIBRARY_PATH, then the "." cwd default. The env step is what
// makes `skills-check policy-check` usable from a user's CI / pre-commit
// without a skills-library checkout in the working directory.
func TestResolveLibraryRoot(t *testing.T) {
	cases := []struct {
		name    string
		flagVal string
		env     string // "" means unset
		want    string
	}{
		{"explicit path beats env", "/explicit/root", "/env/root", "/explicit/root"},
		{"explicit path, no env", "/explicit/root", "", "/explicit/root"},
		{"dot default falls through to env", ".", "/env/root", "/env/root"},
		{"empty falls through to env", "", "/env/root", "/env/root"},
		{"dot default, no env, stays cwd", ".", "", "."},
		{"empty, no env, becomes cwd", "", "", "."},
		{"env is trimmed", ".", "  /env/root  ", "/env/root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.env == "" {
				os.Unsetenv("SKILLS_LIBRARY_PATH")
			} else {
				t.Setenv("SKILLS_LIBRARY_PATH", tc.env)
			}
			if got := resolveLibraryRoot(tc.flagVal); got != tc.want {
				t.Errorf("resolveLibraryRoot(%q) with env %q = %q; want %q",
					tc.flagVal, tc.env, got, tc.want)
			}
		})
	}
}

// run executes one subcommand against the real repo and returns
// stdout, stderr, and the resulting error. The returned error is
// whatever the RunE handler produced — *not* an os.Exit — so tests
// can branch on the policy-failure sentinel.
func run(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := Root()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestCheckDependencyHappyPath(t *testing.T) {
	out, _, err := run(t,
		"check-dependency",
		"--path", repoRootForTest(t),
		"--package", "express",
		"--version", "4.18.0",
		"--ecosystem", "npm",
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// The fix from PR #1 means express@npm should return NO Java CVEs;
	// the heading is the only thing that must appear.
	if !strings.Contains(out, "check-dependency express@4.18.0 (npm)") {
		t.Errorf("expected heading missing\n%s", out)
	}
	if !strings.Contains(out, "CVE pattern hits:   0") {
		t.Errorf("express@npm leaked a CVE pattern hit (regression of PR #1):\n%s", out)
	}
}

func TestCheckDependencyJSONFormat(t *testing.T) {
	out, _, err := run(t,
		"check-dependency",
		"--path", repoRootForTest(t),
		"--package", "express",
		"--version", "4.18.0",
		"--ecosystem", "npm",
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	var got map[string]interface{}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("invalid JSON output: %v\n%s", err, out)
	}
	if got["package"] != "express" || got["ecosystem"] != "npm" {
		t.Errorf("JSON payload missing expected fields: %v", got)
	}
}

func TestCheckDependencyRejectsMissingArgs(t *testing.T) {
	_, _, err := run(t, "check-dependency", "--path", repoRootForTest(t), "--ecosystem", "npm")
	if err == nil {
		t.Fatal("expected error for missing --package, got nil")
	}
	if !strings.Contains(err.Error(), "package") {
		t.Errorf("error does not mention package: %v", err)
	}
}

func TestCheckDependencyRejectsUnknownFormat(t *testing.T) {
	_, _, err := run(t,
		"check-dependency",
		"--path", repoRootForTest(t),
		"--package", "express",
		"--ecosystem", "npm",
		"--format", "xml",
	)
	if err == nil {
		t.Fatal("expected error for --format xml")
	}
	if !strings.Contains(err.Error(), "format") {
		t.Errorf("error does not mention format: %v", err)
	}
}

func TestCheckTyposquatLodahs(t *testing.T) {
	out, _, err := run(t,
		"check-typosquat",
		"--path", repoRootForTest(t),
		"--package", "lodahs",
		"--ecosystem", "npm",
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// lodahs is the canonical typosquat example in the bundled DB.
	if !strings.Contains(out, "target=lodash") {
		t.Errorf("lodahs did not resolve to lodash:\n%s", out)
	}
}

func TestLookupVulnerabilityEventStream(t *testing.T) {
	out, _, err := run(t,
		"lookup-vulnerability",
		"--path", repoRootForTest(t),
		"--package", "event-stream",
		"--ecosystem", "npm",
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// event-stream is the canonical malicious-package example.
	if !strings.Contains(out, "Malicious matches:") {
		t.Errorf("output missing Malicious counter:\n%s", out)
	}
}

func TestScanSecretsOnFixture(t *testing.T) {
	// Drop a temp file with one obvious Stripe key in it. The bundled
	// DLP rules must catch it.
	tmp, err := os.CreateTemp(t.TempDir(), "secret-*.txt")
	if err != nil {
		t.Fatal(err)
	}
	const fake = "STRIPE_KEY = \"sk_live_51H8xYzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdef\""
	if _, err := tmp.WriteString(fake); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	out, _, err := run(t,
		"scan-secrets",
		"--path", repoRootForTest(t),
		tmp.Name(),
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "Matches: ") {
		t.Errorf("scan-secrets did not print matches header:\n%s", out)
	}
	// We don't assert on a specific rule name here because the exact
	// DLP pattern label may evolve; the count just needs to be > 0.
	if strings.Contains(out, "Matches: 0") {
		t.Errorf("scan-secrets missed a Stripe live key in fixture:\n%s", out)
	}
}

func TestScanDockerfileOnFixture(t *testing.T) {
	tmp, err := os.CreateTemp(t.TempDir(), "Dockerfile-*")
	if err != nil {
		t.Fatal(err)
	}
	const docker = `FROM node:latest
USER root
ADD https://example.com/foo.tar.gz /
RUN curl http://example.com | sh
EXPOSE 3000
CMD ["node", "server.js"]
`
	if _, err := tmp.WriteString(docker); err != nil {
		t.Fatal(err)
	}
	tmp.Close()
	out, _, err := run(t,
		"scan-dockerfile",
		"--path", repoRootForTest(t),
		tmp.Name(),
	)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	// :latest, USER root, ADD remote, curl|sh — at least one of those
	// must surface as a finding.
	if strings.Contains(out, "Findings: 0") {
		t.Errorf("scan-dockerfile missed obvious anti-patterns in fixture:\n%s", out)
	}
}

// policy_check dispatches scanners by file basename: "Dockerfile" →
// scan_dockerfile, lockfile names → scan_dependencies, etc. So tests
// for policy-check must use the canonical basename inside an
// otherwise-unique temp directory, not a unique filename.
func writeFixedNameFixture(t *testing.T, basename, body string) string {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, basename)
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

func TestPolicyCheckFailsOnBadDockerfile(t *testing.T) {
	const docker = `FROM node:latest
USER root
RUN curl http://example.com | sh
`
	path := writeFixedNameFixture(t, "Dockerfile", docker)
	out, _, err := run(t,
		"policy-check",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		path,
	)
	if err == nil {
		t.Fatalf("policy-check did not signal failure for bad Dockerfile:\n%s", out)
	}
	if !IsPolicyFailure(err) {
		t.Errorf("expected policy-failure sentinel, got %T: %v", err, err)
	}
	if !strings.Contains(out, "FAIL") {
		t.Errorf("output does not show FAIL verdict:\n%s", out)
	}
}

func TestPolicyCheckPassesOnCleanDockerfile(t *testing.T) {
	const docker = `FROM node:18@sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
USER 10001
RUN echo "no remote fetch, no curl|sh"
HEALTHCHECK CMD true
CMD ["node", "server.js"]
`
	path := writeFixedNameFixture(t, "Dockerfile", docker)
	out, _, err := run(t,
		"policy-check",
		"--path", repoRootForTest(t),
		"--severity-floor", "high",
		path,
	)
	if err != nil {
		t.Fatalf("policy-check failed on clean Dockerfile (unexpected): %v\n%s", err, out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("output does not show PASS verdict:\n%s", out)
	}
}

func TestPolicyFailureSentinelIsDistinguishable(t *testing.T) {
	// IsPolicyFailure is exported so external callers (and a future
	// outer wrapper) can branch on "findings found" vs "tool errored".
	// Verify the predicate distinguishes the two paths correctly.
	err := &policyFailureError{count: 3, floor: "high"}
	if !IsPolicyFailure(err) {
		t.Error("IsPolicyFailure should accept *policyFailureError")
	}
	if IsPolicyFailure(errors.New("some other error")) {
		t.Error("IsPolicyFailure should reject unrelated errors")
	}
	if IsPolicyFailure(nil) {
		t.Error("IsPolicyFailure should reject nil")
	}
	want := "policy-check: 3 finding(s) at or above high"
	if got := err.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
