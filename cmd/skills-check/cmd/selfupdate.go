package cmd

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/namncqualgo/skills-library/cmd/skills-check/internal/manifest"
)

// DefaultSelfUpdateBaseURL is the GitHub Releases "latest" endpoint that
// hosts the skills-check binaries and the matching per-target SHA-256
// checksum files.
const DefaultSelfUpdateBaseURL = "https://github.com/namncqualgo/skills-library/releases/latest/download"

func selfUpdateCmd() *cobra.Command {
	var baseURL string
	var dryRun bool
	c := &cobra.Command{
		Use:   "self-update",
		Short: "Download the latest skills-check binary and atomically replace this one",
		Long: "Downloads the binary that matches the running GOOS/GOARCH from " +
			"GitHub Releases, verifies a detached Ed25519 signature over the " +
			"checksums-<goos>-<goarch>.txt file against the public key embedded " +
			"in this binary (fail-closed for released builds), checks the binary's " +
			"SHA-256 against that signed checksum, and atomically replaces the " +
			"running binary on disk. --dry-run reports what would happen " +
			"without writing anything.",
		RunE: func(c *cobra.Command, args []string) error {
			if baseURL == "" {
				baseURL = DefaultSelfUpdateBaseURL
			}
			exe, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolve current binary: %w", err)
			}
			result, err := runSelfUpdate(c.OutOrStdout(), baseURL, runtime.GOOS, runtime.GOARCH, exe, dryRun)
			if err != nil {
				return err
			}
			out := c.OutOrStdout()
			fmt.Fprintf(out, "verified %s (sha256 %s)\n", result.BinaryName, result.SHA256)
			if dryRun {
				fmt.Fprintln(out, "dry-run: not replacing on-disk binary")
				return nil
			}
			fmt.Fprintf(out, "replaced %s\n", exe)
			return nil
		},
	}
	c.Flags().StringVar(&baseURL, "base-url", DefaultSelfUpdateBaseURL,
		"override the base URL the binary and checksum file are fetched from")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "verify the download without replacing the on-disk binary")
	return c
}

type selfUpdateResult struct {
	BinaryName string
	SHA256     string
}

// runSelfUpdate is split out from the cobra RunE so the test can exercise
// it directly against an httptest.Server without re-wiring cobra.
func runSelfUpdate(out io.Writer, baseURL, goos, goarch, targetPath string, dryRun bool) (*selfUpdateResult, error) {
	binaryName := fmt.Sprintf("skills-check-%s-%s", goos, goarch)
	if goos == "windows" {
		binaryName += ".exe"
	}
	checksumName := fmt.Sprintf("checksums-%s-%s.txt", goos, goarch)

	binURL, err := joinURL(baseURL, binaryName)
	if err != nil {
		return nil, err
	}
	sumURL, err := joinURL(baseURL, checksumName)
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "downloading %s\n", binURL)

	body, err := httpGet(binURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", binURL, err)
	}
	defer body.Close()
	binaryBytes, err := io.ReadAll(body)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", binURL, err)
	}

	fmt.Fprintf(out, "downloading %s\n", sumURL)
	sumBody, err := httpGet(sumURL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", sumURL, err)
	}
	sumBytes, err := io.ReadAll(sumBody)
	sumBody.Close()
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", sumURL, err)
	}

	// Anchor trust to the project's Ed25519 release key, not the download
	// source. Without this, a compromised release (or a malicious --base-url)
	// can serve a binary plus a matching checksum file and the SHA-256 check
	// passes vacuously. We verify a detached signature over the checksum file
	// bytes using the public key embedded in this binary at build time. When a
	// key is embedded (every released build), this is fail-closed: a missing or
	// invalid signature aborts the update. Dev builds with no embedded key
	// cannot verify and fall back to checksum-only with a clear warning.
	if err := verifyChecksumSignature(out, baseURL, checksumName, sumBytes); err != nil {
		return nil, err
	}

	expected, err := lookupChecksum(strings.NewReader(string(sumBytes)), binaryName)
	if err != nil {
		return nil, err
	}
	got := sha256.Sum256(binaryBytes)
	gotHex := hex.EncodeToString(got[:])
	if !strings.EqualFold(gotHex, expected) {
		return nil, fmt.Errorf("sha256 mismatch for %s: got %s want %s", binaryName, gotHex, expected)
	}
	if dryRun {
		return &selfUpdateResult{BinaryName: binaryName, SHA256: gotHex}, nil
	}
	if err := manifest.WriteFileAtomic(targetPath, binaryBytes, 0o755); err != nil {
		return nil, fmt.Errorf("replace %s: %w", targetPath, err)
	}
	return &selfUpdateResult{BinaryName: binaryName, SHA256: gotHex}, nil
}

// verifyChecksumSignature downloads "<checksumName>.sig" and verifies it is a
// valid Ed25519 signature over sumBytes using the public key embedded in this
// binary. Fail-closed when a key is embedded; warn-and-continue only for dev
// builds that have no key to verify against.
func verifyChecksumSignature(out io.Writer, baseURL, checksumName string, sumBytes []byte) error {
	pub, err := manifest.EmbeddedPublicKeyParsed()
	if err != nil {
		// No key embedded — a development build. There is nothing to verify
		// against; preserve the legacy checksum-only behaviour but say so
		// loudly so it is never mistaken for a verified update.
		fmt.Fprintln(out, "warning: no release signing key embedded in this build; "+
			"skipping signature verification (checksum-only). Released binaries verify the signature.")
		return nil
	}
	sigURL, err := joinURL(baseURL, checksumName+".sig")
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "downloading %s\n", sigURL)
	sigBody, err := httpGet(sigURL)
	if err != nil {
		return fmt.Errorf("download release signature %s: %w "+
			"(refusing to update without a verifiable signature)", sigURL, err)
	}
	sigRaw, err := io.ReadAll(sigBody)
	sigBody.Close()
	if err != nil {
		return fmt.Errorf("read release signature %s: %w", sigURL, err)
	}
	if err := manifest.VerifyDetached(pub, sumBytes, string(sigRaw)); err != nil {
		return fmt.Errorf("release signature verification failed for %s: %w "+
			"(the checksum file is not signed by the trusted release key)", checksumName, err)
	}
	fmt.Fprintf(out, "verified release signature (key %s)\n", manifest.EmbeddedKeyDisplay())
	return nil
}

func joinURL(base, name string) (string, error) {
	u, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("parse base url %s: %w", base, err)
	}
	u.Path = path.Join(u.Path, name)
	return u.String(), nil
}

func httpGet(u string) (io.ReadCloser, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		resp.Body.Close()
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

// lookupChecksum scans a `sha256sum`-style file (one entry per line:
// "<hex>  <filename>") and returns the hex digest for the file matching
// binaryName.
func lookupChecksum(r io.Reader, binaryName string) (string, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		hash := fields[0]
		name := strings.TrimPrefix(fields[len(fields)-1], "*")
		if name == binaryName {
			return strings.ToLower(hash), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("checksum for %s not found", binaryName)
}
