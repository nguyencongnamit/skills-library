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

	"github.com/kennguy3n/skills-library/cmd/skills-check/internal/manifest"
)

// DefaultSelfUpdateBaseURL is the GitHub Releases "latest" endpoint that
// hosts the skills-check binaries and the matching per-target SHA-256
// checksum files.
const DefaultSelfUpdateBaseURL = "https://github.com/kennguy3n/skills-library/releases/latest/download"

func selfUpdateCmd() *cobra.Command {
	var baseURL string
	var dryRun bool
	c := &cobra.Command{
		Use:   "self-update",
		Short: "Download the latest skills-check binary and atomically replace this one",
		Long: "Downloads the binary that matches the running GOOS/GOARCH from " +
			"GitHub Releases, verifies its SHA-256 against the published " +
			"checksums-<goos>-<goarch>.txt file, and atomically replaces the " +
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
	defer sumBody.Close()

	expected, err := lookupChecksum(sumBody, binaryName)
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
