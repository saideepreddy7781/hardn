# Homebrew formula template. Copy to Formula/hardn.rb in a tap repo named `homebrew-tap`
# and set `sha256` after each GitHub release (the PyPI name `hardn` belongs to another project).
class Hardn < Formula
  include Language::Python::Virtualenv

  desc "Offline security scanner that turns findings into an AI-ready fix prompt"
  homepage "https://github.com/saideepreddy7781/hardn"
  url "https://github.com/saideepreddy7781/hardn/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "SET_FROM_THE_TAG_TARBALL"
  license "Apache-2.0"

  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/hardn --version")
  end
end
