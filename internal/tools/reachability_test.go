package tools

import (
	"os"
	"path/filepath"
	"testing"
)

func importSpecSet(refs []importRef) map[string]bool {
	m := map[string]bool{}
	for _, r := range refs {
		m[r.spec] = true
	}
	return m
}

func mkProjFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func reachOf(rep *ReachabilityReport, pkg string) *ReachabilityFinding {
	for i := range rep.Findings {
		if rep.Findings[i].Package == pkg {
			return &rep.Findings[i]
		}
	}
	return nil
}

func TestJSPackageName(t *testing.T) {
	cases := map[string]string{
		"lodash":         "lodash",
		"lodash/fp":      "lodash",
		"@scope/pkg":     "@scope/pkg",
		"@scope/pkg/sub": "@scope/pkg",
		"./local":        "",
		"../up":          "",
		"/abs":           "",
		"":               "",
	}
	for in, want := range cases {
		if got := jsPackageName(in); got != want {
			t.Errorf("jsPackageName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExtractJSImports(t *testing.T) {
	src := `import fs from 'fs';
import { merge } from "lodash/fp";
const ev = require('event-stream');
const dyn = await import("@scope/thing/sub");
import './side-effect';
import x from './local';
// import commented from 'evil'
export { a } from 'reexported';`
	got := importSpecSet(extractJSImports(src, "a.js"))
	for _, want := range []string{"fs", "lodash", "event-stream", "@scope/thing", "reexported"} {
		if !got[want] {
			t.Errorf("expected JS import %q in %v", want, got)
		}
	}
	for _, no := range []string{"evil", "./local", "./side-effect"} {
		if got[no] {
			t.Errorf("did not expect %q (relative/commented) in %v", no, got)
		}
	}
}

func TestExtractPyImports(t *testing.T) {
	src := `import os
import numpy as np
import requests, flask
from django.db import models
from . import sibling
from .relative import x
# import commented
import collections.abc`
	got := importSpecSet(extractPyImports(src, "a.py"))
	for _, want := range []string{"os", "numpy", "requests", "flask", "django", "collections"} {
		if !got[want] {
			t.Errorf("expected Py import %q in %v", want, got)
		}
	}
	for _, no := range []string{"sibling", "commented", "relative", "x"} {
		if got[no] {
			t.Errorf("relative/commented import leaked %q: %v", no, got)
		}
	}
}

func TestExtractGoImports(t *testing.T) {
	src := `package main

import "fmt"
import _ "github.com/lib/pq"

import (
	"os"
	mrand "math/rand"
	"github.com/evil/pkg"
	// "github.com/commented/out"
)`
	got := importSpecSet(extractGoImports(src, "a.go"))
	for _, want := range []string{"fmt", "github.com/lib/pq", "os", "math/rand", "github.com/evil/pkg"} {
		if !got[want] {
			t.Errorf("expected Go import %q in %v", want, got)
		}
	}
	if got["github.com/commented/out"] {
		t.Errorf("commented import leaked: %v", got)
	}
}

func TestMatchImportGoIsSegmentExact(t *testing.T) {
	refs := []importRef{{spec: "github.com/foo/bar/baz", file: "a.go", line: 3}}
	if sites := matchImport("go", "github.com/foo/bar", refs); len(sites) != 1 {
		t.Errorf("a go module should match a subpackage import, got %v", sites)
	}
	// Substring-but-not-segment must NOT match (…/bar is not …/ba).
	if sites := matchImport("go", "github.com/foo/ba", refs); len(sites) != 0 {
		t.Errorf("go match must be path-segment exact, not substring; got %v", sites)
	}
}

func TestMatchImportPyNormalization(t *testing.T) {
	refs := []importRef{{spec: "flask_cors", file: "a.py", line: 1}}
	if sites := matchImport("pypi", "Flask-Cors", refs); len(sites) != 1 {
		t.Errorf("a PyPI distribution name should match its underscored module via normalization, got %v", sites)
	}
}

func TestAnalyzeReachabilityImported(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	// event-stream@3.3.6 is the canonical compromised release in the
	// bundled malicious-package DB, so the finding is deterministic/offline.
	mkProjFile(t, filepath.Join(dir, "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"node_modules/event-stream":{"version":"3.3.6"}}}`)
	mkProjFile(t, filepath.Join(dir, "src", "index.js"),
		"const es = require('event-stream');\n")
	rep, err := lib.AnalyzeReachability(dir)
	if err != nil {
		t.Fatalf("AnalyzeReachability: %v", err)
	}
	f := reachOf(rep, "event-stream")
	if f == nil {
		t.Fatalf("expected a finding for event-stream; got %+v", rep.Findings)
	}
	if !f.Analyzed || !f.Imported {
		t.Errorf("event-stream should be analyzed+imported, got analyzed=%v imported=%v", f.Analyzed, f.Imported)
	}
	if len(f.Sites) == 0 || filepath.ToSlash(f.Sites[0].File) != "src/index.js" {
		t.Errorf("expected import site src/index.js, got %+v", f.Sites)
	}
	if rep.ImportedCount < 1 {
		t.Errorf("imported_count should be >=1, got %d", rep.ImportedCount)
	}
}

func TestAnalyzeReachabilityNotImported(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	mkProjFile(t, filepath.Join(dir, "package-lock.json"),
		`{"lockfileVersion":3,"packages":{"node_modules/event-stream":{"version":"3.3.6"}}}`)
	// Source imports a different package — the flagged one is present in the
	// lockfile but not directly imported.
	mkProjFile(t, filepath.Join(dir, "src", "index.js"),
		"const x = require('lodash');\n")
	rep, err := lib.AnalyzeReachability(dir)
	if err != nil {
		t.Fatalf("AnalyzeReachability: %v", err)
	}
	f := reachOf(rep, "event-stream")
	if f == nil {
		t.Fatalf("expected a finding for event-stream; got %+v", rep.Findings)
	}
	if !f.Analyzed {
		t.Error("an npm finding should be analyzed")
	}
	if f.Imported {
		t.Errorf("event-stream is not imported (only lodash is); got imported=true sites=%+v", f.Sites)
	}
}

func TestAnalyzeReachabilityNoFindings(t *testing.T) {
	lib := newLibrary(t)
	dir := t.TempDir()
	mkProjFile(t, filepath.Join(dir, "go.sum"),
		"github.com/stretchr/testify v1.8.4 h1:abc=\n")
	rep, err := lib.AnalyzeReachability(dir)
	if err != nil {
		t.Fatalf("AnalyzeReachability: %v", err)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("a clean project has no flagged deps to triage, got %d", len(rep.Findings))
	}
	if rep.Findings == nil {
		t.Error("Findings should be non-nil ([]) for stable JSON")
	}
}
