# The builder's minimal enclave kernels, their configs and its static
# aarch64 init, built from the builder's source (the `builder-src` input)
# with the builder's nixpkgs pin (the `nixpkgs-builder` input).
#
# This repeats the kernel and init recipes in EnclaviaIO/builder's
# flake.nix at the pinned rev. Given the same source files and the same
# nixpkgs, it yields the same derivations as the builder's
# `enclave-kernel`, `enclave-kernel-config`, `enclave-kernel-aarch64`,
# `enclave-kernel-config-aarch64` and `eif-init-aarch64` outputs: same
# .drv paths, same store paths. The builder imports nixpkgs with
# rust-overlay applied; the overlay only adds Rust toolchains and changes
# nothing these derivations use.
#
# Keep it in step with the builder's flake.nix when `builder-src` moves.
# The builder is not a flake input here because its flake has an
# `enclavia` input pointing back at this repo (see flake.nix).
{
  # nixpkgs at the builder's pinned rev, for x86_64-linux.
  pkgs,
  # The builder's source tree.
  builderSrc,
}:

let
  # Both profiles use the kernel nixpkgs ships as linuxPackages_latest.
  kernelSource = pkgs.linuxPackages_latest.kernel;

  # The aarch64 (Graviton) profile is cross-built on x86_64-linux.
  aarch64Cross = pkgs.pkgsCross.aarch64-multiplatform;
in
rec {
  # Non-storage profile: the builder's `enclave-kernel-config` and
  # `enclave-kernel` (bzImage).
  kernelConfig = pkgs.callPackage "${builderSrc}/nix/kernel-config.nix" {
    kernel = kernelSource;
  };
  kernel = pkgs.linuxManualConfig {
    version = kernelSource.version;
    src = kernelSource.src;
    configfile = "${kernelConfig}/config";
    allowImportFromDerivation = true;
  };

  # aarch64 base profile: the builder's `enclave-kernel-config-aarch64`
  # and `enclave-kernel-aarch64` (Image).
  kernelConfigAarch64 = pkgs.callPackage "${builderSrc}/nix/kernel-config.nix" {
    kernel = kernelSource;
    kernelArch = "aarch64";
    crossCc = aarch64Cross.stdenv.cc;
  };
  kernelAarch64 = aarch64Cross.linuxManualConfig {
    version = kernelSource.version;
    src = kernelSource.src;
    configfile = "${kernelConfigAarch64}/config";
    allowImportFromDerivation = true;
  };

  # Static aarch64 build of the patched init: the builder's
  # `eif-init-aarch64` (bin/init).
  initAarch64 = pkgs.callPackage "${builderSrc}/nix/eif-init-static-cross.nix" {
    goArch = "arm64";
  };
}
