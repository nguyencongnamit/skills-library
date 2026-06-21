# Makefile for SecureVibe (github.com/namncqualgo/skills-library)
#
# Thin wrappers around the commands documented in CONTRIBUTING.md so the
# build / test / validate flow is one `make <target>` away. The Go
# module path stays github.com/namncqualgo/skills-library and the
# binaries stay skills-check / skills-mcp (stable technical identifiers).

# Build flags: -trimpath strips local filesystem paths from the binary;
# -s -w drop the symbol table and DWARF tables for a smaller binary.
GO         ?= go
GOFLAGS    ?= -trimpath
LDFLAGS    ?= -s -w
BIN_DIR    ?= .
SKILLS_CHECK := $(BIN_DIR)/skills-check
SKILLS_MCP   := $(BIN_DIR)/skills-mcp

# Every .go file (excluding the VCS dir) is a prerequisite of both binaries so
# Make rebuilds them whenever a source changes. WITHOUT this, the binary file
# targets look "up to date" the moment they exist, and `make validate` /
# `regenerate` silently run a STALE binary against fresh source — which once
# produced phantom token-budget failures (the stale-./skills-check footgun
# noted in CLAUDE.md). Source-dependency tracking keeps `make validate` fresh.
GO_SOURCES := $(shell find . -name '*.go' -not -path './.git/*' 2>/dev/null)

.DEFAULT_GOAL := build

.PHONY: build
build: $(SKILLS_CHECK) $(SKILLS_MCP) ## Build both binaries (default)

# These are FILE targets (not phony) with the .go sources as prerequisites, so
# they rebuild on a source change but no-op when up to date. GNU Make
# canonicalises `./skills-check` to `skills-check`, so `make skills-check` /
# `make skills-mcp` still work as before — no separate phony aliases needed
# (and a phony alias would create a circular self-dependency).
$(SKILLS_CHECK): $(GO_SOURCES)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(SKILLS_CHECK) ./cmd/skills-check

$(SKILLS_MCP): $(GO_SOURCES)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(SKILLS_MCP) ./cmd/skills-mcp

.PHONY: test
test: ## Run the full Go test suite
	$(GO) test ./...

.PHONY: vet
vet: ## Run go vet across all packages
	$(GO) vet ./...

.PHONY: fmt
fmt: ## Format all Go sources with gofmt
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if any Go source is not gofmt-clean
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed on:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: validate
validate: $(SKILLS_CHECK) ## Validate every skill + rule file
	$(SKILLS_CHECK) validate

.PHONY: regenerate
regenerate: $(SKILLS_CHECK) ## Re-render dist/ (commit any drift)
	$(SKILLS_CHECK) regenerate

.PHONY: check
check: fmt-check vet test validate ## Run the local pre-PR gate

# --- Docs site (mkdocs-material) --------------------------------------------
# The `social` (OG-card) and `privacy` (font self-hosting) plugins need
# CairoSVG, which dlopens libcairo from Homebrew — export the lib path so the
# build finds it. VENV defaults to the in-repo .venv; override if elsewhere.
VENV       ?= .venv
CAIRO_LIB  ?= /opt/homebrew/lib

.PHONY: docs
docs: ## Build the docs site (social cards + self-hosted fonts), strict
	DYLD_FALLBACK_LIBRARY_PATH=$(CAIRO_LIB):$$DYLD_FALLBACK_LIBRARY_PATH \
		$(VENV)/bin/mkdocs build --strict

.PHONY: docs-serve
docs-serve: ## Live-reload docs preview on http://127.0.0.1:8000
	DYLD_FALLBACK_LIBRARY_PATH=$(CAIRO_LIB):$$DYLD_FALLBACK_LIBRARY_PATH \
		$(VENV)/bin/mkdocs serve

.PHONY: wasm
wasm: ## Build the in-browser playground WASM (real scanners, embedded data)
	@echo "populating wasm/embed/ from the real data tree..."
	rm -rf wasm/embed
	mkdir -p wasm/embed/vulnerabilities/supply-chain/malicious-packages \
	         wasm/embed/vulnerabilities/supply-chain/typosquat-db \
	         wasm/embed/skills/secret-detection/checklists
	cp vulnerabilities/supply-chain/malicious-packages/*.json wasm/embed/vulnerabilities/supply-chain/malicious-packages/
	cp vulnerabilities/supply-chain/typosquat-db/known_typosquats.json wasm/embed/vulnerabilities/supply-chain/typosquat-db/
	cp skills/secret-detection/checklists/secret_detection.yaml wasm/embed/skills/secret-detection/checklists/
	mkdir -p docs/assets/playground
	GOOS=js GOARCH=wasm $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o docs/assets/playground/skills.wasm ./wasm
	cp "$$($(GO) env GOROOT)/lib/wasm/wasm_exec.js" docs/assets/playground/wasm_exec.js
	@ls -lh docs/assets/playground/skills.wasm | awk '{print "  built docs/assets/playground/skills.wasm ("$$5")"}'

.PHONY: demo-gif
demo-gif: $(SKILLS_CHECK) ## Re-record the hero terminal demo (needs vhs)
	@command -v vhs >/dev/null || { echo "vhs not installed: brew install vhs"; exit 1; }
	rm -rf /tmp/sv-hero-demo && mkdir -p /tmp/sv-hero-demo/bin
	cp $(SKILLS_CHECK) /tmp/sv-hero-demo/bin/secure-code-check
	printf 'requests==2.31.0\ncolourama==0.4.6\n' > /tmp/sv-hero-demo/requirements.txt
	printf 'GITHUB_TOKEN = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"\nSTRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcAbCdEfGhItuv"\n' > /tmp/sv-hero-demo/config.py
	PATH="/tmp/sv-hero-demo/bin:$$PATH" vhs docs/assets/demo.tape

.PHONY: clean
clean: ## Remove built binaries
	rm -f $(SKILLS_CHECK) $(SKILLS_MCP)

.PHONY: help
help: ## List available targets
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'
