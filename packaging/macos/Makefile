# Makefile for building a macOS .pkg installer for skills-check.
#
# Prerequisites:
#   - macOS with Xcode Command Line Tools (pkgbuild, productbuild)
#   - Pre-built skills-check universal or platform binary at $(BINARY)
#
# Usage:
#   make BINARY=../../dist-build/skills-check-darwin-arm64 VERSION=2026.05.12
#   # produces: build/skills-check-$(VERSION).pkg

BINARY   ?= ../../skills-check
VERSION  ?= 0.0.0
INSTALL_DIR = /usr/local/bin
IDENTIFIER = com.skills-library.skills-check
BUILD_DIR  = build
PKG_ROOT   = $(BUILD_DIR)/pkg-root

.PHONY: all clean

all: $(BUILD_DIR)/skills-check-$(VERSION).pkg

$(BUILD_DIR)/skills-check-$(VERSION).pkg: $(BUILD_DIR)/component.pkg distribution.xml
	productbuild \
		--distribution distribution.xml \
		--package-path $(BUILD_DIR) \
		--version "$(VERSION)" \
		$@

$(BUILD_DIR)/component.pkg: $(PKG_ROOT)$(INSTALL_DIR)/skills-check
	pkgbuild \
		--identifier "$(IDENTIFIER)" \
		--version "$(VERSION)" \
		--root $(PKG_ROOT) \
		--install-location / \
		$@

$(PKG_ROOT)$(INSTALL_DIR)/skills-check: $(BINARY)
	mkdir -p $(dir $@)
	cp $(BINARY) $@
	chmod 755 $@

clean:
	rm -rf $(BUILD_DIR)
