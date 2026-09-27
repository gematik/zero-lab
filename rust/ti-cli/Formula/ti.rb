# Template for the tap's Formula/ti.rb; `just publish-brew` fills in the placeholders.
class Ti < Formula
  desc "Command-line tool for the gematik Telematikinfrastruktur (TI)"
  homepage "https://github.com/gematik/zero-lab/tree/main/rust/ti-cli"
  version "@VERSION@"
  license "Apache-2.0"

  on_macos do
    on_arm do
      url "@URL_aarch64-apple-darwin@"
      sha256 "@SHA256_aarch64-apple-darwin@"
    end
    on_intel do
      url "@URL_x86_64-apple-darwin@"
      sha256 "@SHA256_x86_64-apple-darwin@"
    end
  end

  on_linux do
    on_arm do
      url "@URL_aarch64-unknown-linux-musl@"
      sha256 "@SHA256_aarch64-unknown-linux-musl@"
    end
    on_intel do
      url "@URL_x86_64-unknown-linux-musl@"
      sha256 "@SHA256_x86_64-unknown-linux-musl@"
    end
  end

  def install
    # The release assets are bare executables, downloaded without the executable bit.
    binary = Dir["ti-*"].first
    chmod 0755, binary
    bin.install binary => "ti"
  end

  test do
    assert_match "ti #{version}", shell_output("#{bin}/ti --version")
  end
end
