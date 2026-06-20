package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/namncqualgo/skills-library/cmd/skills-check/internal/manifest"
)

// setEmbeddedKey temporarily bakes a public key into the manifest package so
// the self-update path runs its fail-closed signature branch (released builds
// always have an embedded key). Restored after the test.
func setEmbeddedKey(t *testing.T, pub ed25519.PublicKey) {
	t.Helper()
	prev, prevID := manifest.EmbeddedPublicKey, manifest.EmbeddedPublicKeyID
	manifest.EmbeddedPublicKey = manifest.EncodePublicKey(pub)
	manifest.EmbeddedPublicKeyID = "test-release-key"
	t.Cleanup(func() {
		manifest.EmbeddedPublicKey, manifest.EmbeddedPublicKeyID = prev, prevID
	})
}

// signedChecksumBody returns the exact checksum-file body the fake server
// serves for `payload`, plus a valid detached signature over it.
func signedChecksumBody(t *testing.T, priv ed25519.PrivateKey, payload []byte) string {
	t.Helper()
	binaryName := fmt.Sprintf("skills-check-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	sum := sha256.Sum256(payload)
	body := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum[:]), binaryName)
	sig, err := manifest.SignDetached(priv, []byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func TestSelfUpdateVerifiesReleaseSignature(t *testing.T) {
	pub, priv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	setEmbeddedKey(t, pub)
	payload := []byte("a properly signed release binary")
	sig := signedChecksumBody(t, priv, payload)
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", runtime.GOOS, runtime.GOARCH)
	alter := func(name string) (string, bool) {
		if name == checksumName+".sig" {
			return sig, true
		}
		return "", false
	}
	srv, _, want := newFakeReleaseServer(t, payload, alter)

	tmp := filepath.Join(t.TempDir(), "skills-check")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	res, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false)
	if err != nil {
		t.Fatalf("self-update with valid signature: %v\n%s", err, out.String())
	}
	if res.SHA256 != want {
		t.Errorf("checksum=%q want %q", res.SHA256, want)
	}
	if !strings.Contains(out.String(), "verified release signature") {
		t.Errorf("expected signature-verified message, got:\n%s", out.String())
	}
	if got, _ := os.ReadFile(tmp); !bytes.Equal(got, payload) {
		t.Errorf("binary not replaced after a verified update")
	}
}

func TestSelfUpdateRejectsMissingSignature(t *testing.T) {
	pub, _, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	setEmbeddedKey(t, pub) // embedded key but the server serves no .sig (404)
	payload := []byte("unsigned but checksum-matching binary")
	srv, _, _ := newFakeReleaseServer(t, payload, nil)

	tmp := filepath.Join(t.TempDir(), "skills-check")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if _, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false); err == nil {
		t.Fatalf("expected fail-closed on missing signature; got nil\n%s", out.String())
	}
	if body, _ := os.ReadFile(tmp); string(body) != "old" {
		t.Errorf("binary must not be replaced when the signature is missing; got %q", string(body))
	}
}

func TestSelfUpdateRejectsBadSignature(t *testing.T) {
	pub, _, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	setEmbeddedKey(t, pub)
	// Sign with a DIFFERENT key than the one embedded → verification must fail.
	_, wrongPriv, err := manifest.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("binary signed by the wrong key")
	badSig := signedChecksumBody(t, wrongPriv, payload)
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", runtime.GOOS, runtime.GOARCH)
	alter := func(name string) (string, bool) {
		if name == checksumName+".sig" {
			return badSig, true
		}
		return "", false
	}
	srv, _, _ := newFakeReleaseServer(t, payload, alter)

	tmp := filepath.Join(t.TempDir(), "skills-check")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if _, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false); err == nil {
		t.Fatalf("expected fail-closed on bad signature; got nil\n%s", out.String())
	}
	if body, _ := os.ReadFile(tmp); string(body) != "old" {
		t.Errorf("binary must not be replaced on a bad signature; got %q", string(body))
	}
}

// newFakeReleaseServer stands up a httptest.Server that mimics GitHub
// Releases: it serves a fixed binary plus the matching SHA-256 checksum
// file for the current GOOS/GOARCH at the same paths the real CLI hits.
func newFakeReleaseServer(t *testing.T, binary []byte, alter func(name string) (string, bool)) (*httptest.Server, string, string) {
	t.Helper()
	binaryName := fmt.Sprintf("skills-check-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", runtime.GOOS, runtime.GOARCH)

	sum := sha256.Sum256(binary)
	hexsum := hex.EncodeToString(sum[:])
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		body, replaced := "", false
		if alter != nil {
			body, replaced = alter(name)
		}
		switch {
		case name == binaryName && !replaced:
			w.Write(binary)
		case name == checksumName && !replaced:
			fmt.Fprintf(w, "%s  %s\n", hexsum, binaryName)
		case replaced:
			fmt.Fprint(w, body)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, binaryName, hexsum
}

func TestSelfUpdateVerifiesChecksum(t *testing.T) {
	payload := []byte("#!/bin/sh\necho fake binary\n")
	srv, _, want := newFakeReleaseServer(t, payload, nil)

	tmp := filepath.Join(t.TempDir(), "skills-check")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	res, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false)
	if err != nil {
		t.Fatalf("self-update: %v\n%s", err, out.String())
	}
	if res.SHA256 != want {
		t.Errorf("checksum=%q, want %q", res.SHA256, want)
	}
	got, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("binary not replaced")
	}
}

func TestSelfUpdateDetectsChecksumMismatch(t *testing.T) {
	payload := []byte("a fresh binary")
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", runtime.GOOS, runtime.GOARCH)
	alter := func(name string) (string, bool) {
		if name == checksumName {
			return "deadbeef  skills-check-tampered\n", true
		}
		return "", false
	}
	srv, _, _ := newFakeReleaseServer(t, payload, alter)

	tmp := filepath.Join(t.TempDir(), "skills-check")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if _, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, false); err == nil {
		t.Fatalf("expected error on missing checksum entry; got nil. output=%s", out.String())
	}
	body, _ := os.ReadFile(tmp)
	if string(body) != "old" {
		t.Errorf("binary should not have been replaced on checksum failure; got %q", string(body))
	}
}

func TestSelfUpdateDryRunDoesNotWrite(t *testing.T) {
	payload := []byte("new binary")
	srv, _, _ := newFakeReleaseServer(t, payload, nil)

	tmp := filepath.Join(t.TempDir(), "skills-check")
	if err := os.WriteFile(tmp, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	if _, err := runSelfUpdate(out, srv.URL, runtime.GOOS, runtime.GOARCH, tmp, true); err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	body, _ := os.ReadFile(tmp)
	if string(body) != "old" {
		t.Errorf("dry-run must not replace the binary; got %q", string(body))
	}
}

func TestLookupChecksumIgnoresStarPrefix(t *testing.T) {
	r := strings.NewReader("abc123  *skills-check-linux-amd64\ndef456  skills-check-windows-amd64.exe\n")
	got, err := lookupChecksum(r, "skills-check-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc123" {
		t.Errorf("got=%q", got)
	}
}
