package cmd

import (
	"bytes"
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
)

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
