# Homebrew formula template for skills-check.
#
# This file is the canonical source for the nguyencongnamit/tap/skills-check formula.
# On release, the "Stamp Homebrew formula" step in .github/workflows/release.yml
# fills the version + per-arch sha256 placeholders below from the binaries built
# for the new tag (the url lines interpolate v#{version}), and publishes the
# stamped result as the `skills-check.rb` asset on the GitHub Release. To update
# the tap, the release manager copies that published asset into the
# nguyencongnamit/homebrew-tap repository (a tap-token-gated push step can automate
# this once the tap repo + secret exist).
class SkillsCheck < Formula
  desc "Skills Library CLI for AI-assisted coding tools"
  homepage "https://github.com/nguyencongnamit/skills-library"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/nguyencongnamit/skills-library/releases/download/v#{version}/skills-check-darwin-arm64"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/nguyencongnamit/skills-library/releases/download/v#{version}/skills-check-darwin-amd64"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/nguyencongnamit/skills-library/releases/download/v#{version}/skills-check-linux-arm64"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/nguyencongnamit/skills-library/releases/download/v#{version}/skills-check-linux-amd64"
      sha256 "REPLACE_WITH_LINUX_AMD64_SHA256"
    end
  end

  def install
    binary = Dir["skills-check-*"].first
    bin.install binary => "skills-check"
  end

  test do
    assert_match "skills-check", shell_output("#{bin}/skills-check version")
  end
end
