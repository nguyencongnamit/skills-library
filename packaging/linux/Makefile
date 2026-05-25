# Makefile for building skills-check Linux .deb and .rpm packages with nfpm.
#
# Prerequisites:
#   - nfpm v2+ (https://nfpm.goreleaser.com/install/)
#   - Pre-built skills-check binary at $(BINARY)
#
# Usage:
#   make BINARY=../../dist-build/skills-check-linux-amd64 VERSION=2026.05.13
#   # produces: build/skills-check_$(VERSION)_amd64.deb
#   #           build/skills-check-$(VERSION).x86_64.rpm

BINARY  ?= ../../skills-check
VERSION ?= 0.0.0
ARCH    ?= amd64

BUILD_DIR = build
NFPM_BIN  ?= nfpm

export BINARY
export VERSION

.PHONY: all deb rpm clean check

all: deb rpm

deb: $(BUILD_DIR)
	$(NFPM_BIN) pkg --config nfpm.yaml --packager deb --target $(BUILD_DIR)/

rpm: $(BUILD_DIR)
	$(NFPM_BIN) pkg --config nfpm.yaml --packager rpm --target $(BUILD_DIR)/

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

check:
	@python3 -c "import yaml; yaml.safe_load(open('nfpm.yaml'))" && echo "nfpm.yaml parses OK"

clean:
	rm -rf $(BUILD_DIR)
