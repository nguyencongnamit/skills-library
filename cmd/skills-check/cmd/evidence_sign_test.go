package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/namncqualgo/skills-library/cmd/skills-check/internal/manifest"
)

// writeTestKey writes a freshly generated Ed25519 private key (raw 64-byte
// form) to a temp file and returns the path plus the matching public key.
func writeTestKey(t *testing.T) (string, []byte) {
	t.Helper()
	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	path := filepath.Join(t.TempDir(), "evidence-signing.key")
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path, pub
}

func sampleReport() EvidenceReport {
	return EvidenceReport{
		Framework:   "SOC 2",
		LibraryRoot: "/tmp/lib",
		ScanTarget:  "/tmp/repo",
		SkillsCount: 29,
		Controls: []ControlEvidence{
			{
				ID:           "CC6.7",
				Title:        "Restriction of Information Transmission",
				Status:       "covered",
				MappedChecks: []string{"scan_secrets"},
				Verification: "findings",
				CheckResults: []CheckResult{{ID: "scan_secrets", Kind: "scanner", Status: "fail", Findings: 1}},
			},
		},
		UnmappedSkills:   []string{},
		UnmappedControls: []string{},
	}
}

func TestSignAndVerifyEvidenceRoundTrip(t *testing.T) {
	keyPath, pub := writeTestKey(t)
	r := sampleReport()

	if err := signEvidence(&r, keyPath); err != nil {
		t.Fatalf("signEvidence: %v", err)
	}
	if r.Signature == "" {
		t.Fatal("signature should be set after signing")
	}
	if err := verifyEvidence(r, pub); err != nil {
		t.Errorf("verifyEvidence should succeed on a freshly signed report: %v", err)
	}
}

func TestVerifyEvidenceDetectsTamper(t *testing.T) {
	keyPath, pub := writeTestKey(t)
	r := sampleReport()
	if err := signEvidence(&r, keyPath); err != nil {
		t.Fatalf("signEvidence: %v", err)
	}

	// Flip a verification verdict — the classic "make it look compliant"
	// tamper. The signature must no longer verify.
	r.Controls[0].Verification = "verified"
	r.Controls[0].CheckResults[0].Status = "pass"
	r.Controls[0].CheckResults[0].Findings = 0

	if err := verifyEvidence(r, pub); err == nil {
		t.Error("verifyEvidence must fail after the report is altered")
	}
}

func TestVerifyEvidenceRejectsUnsigned(t *testing.T) {
	_, pub := writeTestKey(t)
	r := sampleReport() // no Signature set
	if err := verifyEvidence(r, pub); err == nil {
		t.Error("verifyEvidence must reject an unsigned report")
	}
}

// TestEvidenceCmdSignProducesVerifiableBundle exercises the --sign flag end
// to end and confirms the emitted JSON bundle verifies against the key.
func TestEvidenceCmdSignProducesVerifiableBundle(t *testing.T) {
	root := repoRoot(t)
	keyPath, pub := writeTestKey(t)

	stdout, stderr, err := executeRoot(t,
		"evidence",
		"--library", root,
		"--framework", "SOC2",
		"--sign", keyPath,
		"--format", "json",
	)
	if err != nil {
		t.Fatalf("evidence --sign failed: %v\nstderr:%s", err, stderr)
	}
	var report EvidenceReport
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, stdout)
	}
	if report.Signature == "" {
		t.Fatal("expected a signature in the emitted bundle")
	}
	if err := verifyEvidence(report, pub); err != nil {
		t.Errorf("emitted bundle should verify against the signing key: %v", err)
	}
}
