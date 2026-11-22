{ pkgs, ... }:
let
  # Roc publishes a static binary in a release tarball for each platform,
  # which is used as-is
  rocReleases = {
    x86_64-linux = {
      target = "linux_x86_64";
      sha256 = "043c426ea85dcdbd427951eaed246f0c10c171d988f2598782233a6dae43379d";
    };
    aarch64-linux = {
      target = "linux_arm64";
      sha256 = "b3e0a9dbc922f3802702a55a1869ad2c2e4f4dc935d8a9d1b26c3612668dff43";
    };
    x86_64-darwin = {
      target = "macos_x86_64";
      sha256 = "ea9b38b5e4708cbe42c92077e816f5241299da1aa3f4c46e8cb933b1aa2af858";
    };
    aarch64-darwin = {
      target = "macos_apple_silicon";
      sha256 = "e8228040c701e130254c72539a1d0f1b150d78c00058747edb0edae51ba5dbc8";
    };
  };
  rocRelease =
    rocReleases.${pkgs.stdenv.hostPlatform.system}
      or (throw "no roc release for ${pkgs.stdenv.hostPlatform.system}");
  roc = pkgs.stdenvNoCC.mkDerivation rec {
    pname = "roc";
    version = "0.1.0_RC1";
    src = pkgs.fetchurl {
      url = "https://github.com/roc-lang/roc/releases/download/${version}/roc-${rocRelease.target}-${version}.tar.gz";
      inherit (rocRelease) sha256;
    };
    # The macOS tarballs ship a darwin/ sysroot next to the binary, so keep the whole directory together
    installPhase = ''
      mkdir -p $out/libexec/roc $out/bin
      cp -r . $out/libexec/roc
      chmod +x $out/libexec/roc/roc
      ln -s $out/libexec/roc/roc $out/bin/roc
    '';
  };
in
{
  packages = [
    pkgs.just
    roc
    # References for the differential test (just diff): GNU sha1sum behaves
    # the same on every platform, and OpenSSL is an independent implementation
    pkgs.coreutils
    pkgs.openssl
  ];

  # One command per line: the test script runs with `set -e`, which ignores a
  # failure anywhere in an `a && b && c` list but the last, so a failing test
  # would otherwise let `devenv test` pass
  enterTest = ''
    just check
    just test-all
    just fmt-check
  '';
}
