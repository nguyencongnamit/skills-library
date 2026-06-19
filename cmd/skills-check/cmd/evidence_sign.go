package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/namncqualgo/skills-library/cmd/skills-check/internal/manifest"
)

// canonicalEvidenceBytes returns the deterministic JSON encoding of a
// report with the "signature" field stripped. Signing and verification
// both hash exactly these bytes, so the encoding must be byte-stable.
//
// It mirrors manifest.CanonicalSigningBytes: marshal the report, decode
// into a generic map, drop "signature", then re-marshal. Go's json.Marshal
// sorts object keys alphabetically for map[string]any (recursively, so
// nested controls/check_results are canonical too).
func canonicalEvidenceBytes(r EvidenceReport) ([]byte, error) {
	dup := r
	dup.Signature = ""
	raw, err := json.Marshal(dup)
	if err != nil {
		return nil, err
	}
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		return nil, err
	}
	delete(generic, "signature")
	return json.Marshal(generic)
}

// signEvidence signs the report in-place with the Ed25519 private key at
// keyPath, storing the detached signature as "ed25519:<base64>". It reuses
// the manifest package's key loader, so the same seed / raw / PEM formats
// are accepted as for manifest signing.
func signEvidence(r *EvidenceReport, keyPath string) error {
	priv, err := manifest.LoadPrivateKey(keyPath)
	if err != nil {
		return err
	}
	if len(priv) != ed25519.PrivateKeySize {
		return fmt.Errorf("ed25519 private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	canon, err := canonicalEvidenceBytes(*r)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, canon)
	r.Signature = manifest.SignaturePrefix + base64.StdEncoding.EncodeToString(sig)
	return nil
}

// truncateSig shortens a signature string for human-readable display.
func truncateSig(sig string) string {
	const n = 24
	if len(sig) <= n {
		return sig
	}
	return sig[:n]
}

// verifyEvidence checks the report's detached signature against pub. It is
// the read side of signEvidence and the basis of tamper detection: any
// change to the report's content (a flipped verdict, an edited finding
// count) changes the canonical bytes and fails verification.
func verifyEvidence(r EvidenceReport, pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("ed25519 public key must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	if r.Signature == "" || r.Signature == manifest.PlaceholderSignature {
		return errors.New("evidence report is unsigned")
	}
	if !strings.HasPrefix(r.Signature, manifest.SignaturePrefix) {
		return fmt.Errorf("evidence signature missing %q prefix", manifest.SignaturePrefix)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Signature, manifest.SignaturePrefix))
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("signature length %d != %d", len(raw), ed25519.SignatureSize)
	}
	canon, err := canonicalEvidenceBytes(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, canon, raw) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}
