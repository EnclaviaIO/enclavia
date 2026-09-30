# The builder's minimal enclave kernels, their configs and its x86_64 and
# static aarch64 inits, built from the builder's source (the `builder-src`
# input) with the builder's nixpkgs pin (the `nixpkgs-builder` input).
#
# This repeats the kernel and init recipes in EnclaviaIO/builder's
# flake.nix and nix/enclave.nix at the pinned rev. Given the same source
# files and the same nixpkgs, it yields the same derivations as the
# builder's `enclave-kernel`, `enclave-kernel-config`,
# `enclave-kernel-aarch64`, `enclave-kernel-config-aarch64` and
# `eif-init-aarch64` outputs and the `eif-init` its x86_64 EIFs boot: same
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

  # The builder's x86_64 init (`patchedInit` in its nix/enclave.nix): its
  # vendored init-patched Go source, vendorHash = null because the source
  # ships its own vendor/ tree. The builder names the source with a path
  # literal (`./init-patched`), which Nix copies to the store as
  # `<hash>-init-patched`; `builtins.path` with that name gives the same
  # store path, and so the same derivation.
  init = pkgs.buildGoModule {
    name = "eif-init";
    src = builtins.path {
      path = "${builderSrc}/nix/init-patched";
      name = "init-patched";
    };
    vendorHash = null;
    env.CGO_ENABLED = 0;
    ldflags = [ "-s" "-w" ];
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
