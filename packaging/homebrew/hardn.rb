# Homebrew formula template. Copy to Formula/hardn.rb in a tap repo named `homebrew-tap`
# and set `sha256` after each PyPI release — see docs/PUBLISHING.md.
class Hardn < Formula
  include Language::Python::Virtualenv

  desc "Offline security scanner that turns findings into an AI-ready fix prompt"
  homepage "https://github.com/saideepreddy7781/hardn"
  url "https://files.pythonhosted.org/packages/source/h/hardn/hardn-0.1.0.tar.gz"
  sha256 "SET_FROM_SHA256SUMS_OR_PYPI"
  license "Apache-2.0"

  depends_on "python@3.13"

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/hardn --version")
  end
end
