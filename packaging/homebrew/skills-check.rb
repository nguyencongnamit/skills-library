# Homebrew formula template for skills-check.
#
# This file is the canonical source for the namncqualgo/tap/skills-check formula.
# On release, the release workflow stamps the @version, @url, and @sha256
# placeholders below with the values for the new tag and pushes the resulting
# .rb to the namncqualgo/homebrew-tap repository.
class SkillsCheck < Formula
  desc "Skills Library CLI for AI-assisted coding tools"
  homepage "https://github.com/namncqualgo/skills-library"
  version "0.0.0"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/namncqualgo/skills-library/releases/download/v#{version}/skills-check-darwin-arm64"
      sha256 "REPLACE_WITH_DARWIN_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/namncqualgo/skills-library/releases/download/v#{version}/skills-check-darwin-amd64"
      sha256 "REPLACE_WITH_DARWIN_AMD64_SHA256"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/namncqualgo/skills-library/releases/download/v#{version}/skills-check-linux-arm64"
      sha256 "REPLACE_WITH_LINUX_ARM64_SHA256"
    end
    on_intel do
      url "https://github.com/namncqualgo/skills-library/releases/download/v#{version}/skills-check-linux-amd64"
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
