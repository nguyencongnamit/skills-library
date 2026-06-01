package parsers

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
)

// parseGoSum reads a `go.sum` file. Each line has the shape:
//
//	<module> <version>[/go.mod] h1:<hash>=
//
// We emit one Dependency per unique (module, version) pair. The
// "/go.mod" suffix on the version distinguishes the module checksum
// from the go.mod checksum but both reference the same resolved
// version, so we strip the suffix and dedupe.
func parseGoSum(body []byte) ([]Dependency, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64*1024), 1<<20)

	var out []Dependency
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		module, version := fields[0], fields[1]
		version = strings.TrimSuffix(version, "/go.mod")
		if module == "" || version == "" {
			continue
		}
		out = append(out, Dependency{
			Name:      module,
			Version:   version,
			Ecosystem: "go",
			Source:    line,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("go: scan go.sum: %w", err)
	}
	return dedupe(out), nil
}
