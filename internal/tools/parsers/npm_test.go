package parsers

import (
	"reflect"
	"testing"
)

// TestNPMPackageLockGraphV3 parses the flat `packages` map (lockfile v2/v3),
// reducing nested install paths to bare package names and collecting
// runtime + optional + peer edges (dev deps excluded).
func TestNPMPackageLockGraphV3(t *testing.T) {
	body := []byte(`{
		"lockfileVersion": 3,
		"packages": {
			"": {"dependencies": {"event-stream": "3.3.6"}},
			"node_modules/event-stream": {
				"version": "3.3.6",
				"dependencies": {"flatmap-stream": "0.1.1"},
				"optionalDependencies": {"opt-pkg": "1.0.0"}
			},
			"node_modules/event-stream/node_modules/flatmap-stream": {"version": "0.1.1"},
			"node_modules/dev-only": {"version": "2.0.0", "dev": true}
		}
	}`)
	g, err := NPMPackageLockGraph(body)
	if err != nil {
		t.Fatalf("NPMPackageLockGraph: %v", err)
	}
	if got, want := g["event-stream"], []string{"flatmap-stream", "opt-pkg"}; !reflect.DeepEqual(got, want) {
		t.Errorf("event-stream edges = %v, want %v (sorted; optional included)", got, want)
	}
	// The root key "" is the project itself; its edges are intentionally dropped
	// because BFS roots come from first-party source imports, not the lockfile
	// root node — so "" carries no outgoing edges in the graph.
	if got, ok := g[""]; ok {
		t.Errorf("root node should contribute no edges, got %v", got)
	}
	// dev-only has no outgoing edges; it is a node only by virtue of being a key.
	if _, ok := g["dev-only"]; ok {
		t.Errorf("dev-only should have no outgoing edges, got %v", g["dev-only"])
	}
}

// TestNPMPackageLockGraphV1 parses the recursive `dependencies` tree (lockfile
// v1), whose edges are each node's `requires`.
func TestNPMPackageLockGraphV1(t *testing.T) {
	body := []byte(`{
		"lockfileVersion": 1,
		"dependencies": {
			"event-stream": {
				"version": "3.3.6",
				"requires": {"flatmap-stream": "0.1.1"},
				"dependencies": {
					"flatmap-stream": {"version": "0.1.1"}
				}
			}
		}
	}`)
	g, err := NPMPackageLockGraph(body)
	if err != nil {
		t.Fatalf("NPMPackageLockGraph: %v", err)
	}
	if got := g["event-stream"]; len(got) != 1 || got[0] != "flatmap-stream" {
		t.Errorf("event-stream edges = %v, want [flatmap-stream]", got)
	}
}

func TestNPMPackageLockGraphInvalid(t *testing.T) {
	if _, err := NPMPackageLockGraph([]byte("not json")); err == nil {
		t.Error("expected an error for malformed JSON")
	}
}

func TestNPMNameFromLockKey(t *testing.T) {
	cases := map[string]string{
		"":                                     "",
		"node_modules/foo":                     "foo",
		"node_modules/@scope/pkg":              "@scope/pkg",
		"node_modules/a/node_modules/b":        "b",
		"node_modules/a/node_modules/@scope/b": "@scope/b",
		"node_modules/a/node_modules/b/node_modules/c": "c",
	}
	for in, want := range cases {
		if got := npmNameFromLockKey(in); got != want {
			t.Errorf("npmNameFromLockKey(%q) = %q, want %q", in, got, want)
		}
	}
}
