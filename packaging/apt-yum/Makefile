# Makefile for the APT / YUM release repositories.
#
# Inputs:
#   ARTIFACTS — directory containing skills-check_*.deb and skills-check-*.rpm
#   VERSION   — release version string (informational; baked into the deb/rpm names already)
#   GPG_KEY   — GPG key id used to sign the APT Release file and the RPM packages
#
# Outputs:
#   site/apt/  — APT repository tree ready to publish to GitHub Pages
#   site/yum/  — YUM repository tree ready to publish to GitHub Pages
#
# Prerequisites:
#   reprepro, createrepo_c, gpg (offline-loaded private half of $GPG_KEY).

ARTIFACTS ?= ../../release
VERSION   ?= 0.0.0
GPG_KEY   ?= skills-library@kennguy3n
SITE      ?= site

APT_ROOT = $(SITE)/apt
YUM_ROOT = $(SITE)/yum

.PHONY: site apt yum clean

site: apt yum

apt: $(APT_ROOT)/conf/distributions
	reprepro --basedir $(APT_ROOT) includedeb stable $(ARTIFACTS)/skills-check_*.deb
	gpg --armor --export $(GPG_KEY) > $(APT_ROOT)/pubkey.gpg

$(APT_ROOT)/conf/distributions:
	mkdir -p $(APT_ROOT)/conf
	printf 'Origin: Skills Library\nLabel: Skills Library\nCodename: stable\nArchitectures: amd64 arm64\nComponents: main\nSignWith: $(GPG_KEY)\n' > $@

yum: $(YUM_ROOT)/packages
	cp $(ARTIFACTS)/skills-check-*.rpm $(YUM_ROOT)/packages/
	rpmsign --define '_gpg_name $(GPG_KEY)' --addsign $(YUM_ROOT)/packages/*.rpm
	createrepo_c $(YUM_ROOT)
	gpg --detach-sign --armor --default-key $(GPG_KEY) $(YUM_ROOT)/repodata/repomd.xml
	gpg --armor --export $(GPG_KEY) > $(YUM_ROOT)/RPM-GPG-KEY-skills-library

$(YUM_ROOT)/packages:
	mkdir -p $@

clean:
	rm -rf $(SITE)
