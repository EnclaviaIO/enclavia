{
  description = "Enclavia open-source crates: in-enclave services, shared protocol types, client SDK, CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane.url = "github:ipetkov/crane";

    # Nitro EIF assembler (kernel + init + ramdisk -> image.eif). Same
    # input the builder uses; do NOT follow our nixpkgs (nitro-util's Go
    # builds break on newer nixpkgs). Only consumed by the dedicated
    # `synchronizer-eif` output below.
    nitro-util.url = "github:monzo/aws-nitro-util";

    # Source-only input carrying the builder's patched init (CID-2
    # heartbeat for QEMU's vhost-device-vsock) and kernel/init blobs we
    # reuse for the synchronizer EIF. `flake = false` so we just get its
    # source tree; override during local development with
    # `--override-input builder-src path:../builder`.
    builder-src = {
      url = "github:EnclaviaIO/builder";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, nitro-util, builder-src }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          overlays = [
            rust-overlay.overlays.default
          ];
          inherit system;
        };

        rustToolchain = pkgs: (pkgs.rust-bin.stable."1.88.0".default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
        });

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        rustSrc = craneLib.cleanCargoSource ./.;

        rustCommonArgs = {
          src = rustSrc;
          strictDeps = true;
          nativeBuildInputs = [ pkgs.pkg-config ];
          buildInputs = [ pkgs.openssl ];
        };

        cargoArtifacts = craneLib.buildDepsOnly rustCommonArgs;

        individualCrateArgs = rustCommonArgs // {
          inherit cargoArtifacts;
          inherit (craneLib.crateNameFromCargoToml { src = rustSrc; }) version;
          doCheck = false;
        };

        nbdClient = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "nbd-client";
            cargoExtraArgs = "-p nbd-client";
          }
        );

        enclaviaEgress = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "enclavia-egress";
            cargoExtraArgs = "-p enclavia-egress";
          }
        );

        mockKms = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "mock-kms";
            cargoExtraArgs = "-p mock-kms";
          }
        );

        enclaviaCrypto = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "enclavia-crypto";
            cargoExtraArgs = "-p enclavia-crypto";
          }
        );

        enclaviaServer = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "enclavia-server";
            cargoExtraArgs = "-p enclavia-server";
          }
        );

        enclaviaSecretsInit = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "enclavia-secrets-init";
            cargoExtraArgs = "-p enclavia-secrets-init";
          }
        );

        enclaviaChainInit = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "enclavia-chain-init";
            cargoExtraArgs = "-p enclavia-chain-init";
          }
        );

        # The CLI: crate name `enclavia-cli`, binary name `enclavia`.
        # Exposed as the flake package `enclavia` so testers can run
        # `nix profile install github:EnclaviaIO/enclavia#enclavia`.
        enclaviaCli = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "enclavia";
            cargoExtraArgs = "-p enclavia-cli";
          }
        );

        # In-enclave synchronizer node binary, built in the `qemu`
        # variant: vsock customer listener + vsock mesh transport (same
        # as `enclave`) but skip-cert-chain attestation, which is what
        # QEMU's self-signing NSM emits. `raft` turns on the replicated
        # cluster path (mesh + openraft). One identical binary runs on
        # all three nodes; identity is injected at runtime (see
        # synchronizer-names-init), never baked in, so PCRs stay equal.
        synchronizer = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "enclavia-synchronizer";
            cargoExtraArgs = "-p synchronizer --features qemu,raft";
          }
        );

        # In-enclave runtime identity fetcher (vsock 5011 -> host names
        # responder). Keeps MESH_SELF_NAME / MESH_PEERS out of the
        # measured image and cmdline so the three nodes share one PCR set.
        synchronizerNamesInit = craneLib.buildPackage (
          individualCrateArgs
          // {
            pname = "synchronizer-names-init";
            cargoExtraArgs = "-p synchronizer-names-init";
          }
        );

        # --- Dedicated synchronizer EIF ---------------------------------
        #
        # NOT the builder's OCI pipeline: the synchronizer is the entire
        # in-enclave payload, so we assemble a minimal EIF directly with
        # monzo's nitroLib.buildEif, reusing the builder's prebuilt
        # kernel/init blobs and its patched (CID-2 heartbeat) init for
        # QEMU debug. See nix/synchronizer-eif.nix for the rationale.
        nitroLib = nitro-util.lib.${system};

        # One EIF for both QEMU and real Nitro: the patched init heartbeats
        # both CIDs (3 + 2), so there is no longer a QEMU-vs-Nitro build
        # variant. (`synchronizer-eif-nitro` is kept below as an alias.)
        synchronizerEif = pkgs.callPackage ./nix/synchronizer-eif.nix {
          inherit pkgs nitroLib;
          synchronizerPkg = synchronizer;
          namesInitPkg = synchronizerNamesInit;
          builderSrc = builder-src;
        };

      in
      {
        devShells.default = pkgs.mkShell {
          buildInputs = [
            (rustToolchain pkgs)
            pkgs.pkg-config
            pkgs.openssl
          ];
        };

        packages = {
          nbd-client = nbdClient;
          enclavia-egress = enclaviaEgress;
          mock-kms = mockKms;
          enclavia-crypto = enclaviaCrypto;
          enclavia-server = enclaviaServer;
          enclavia-secrets-init = enclaviaSecretsInit;
          enclavia-chain-init = enclaviaChainInit;
          # Beta-tester install entry point. Must stay named `enclavia`
          # so `nix profile install ...#enclavia` matches the binary.
          enclavia = enclaviaCli;

          # Synchronizer node binary (qemu variant) + its runtime
          # identity fetcher, plus the dedicated EIF that wraps them.
          synchronizer = synchronizer;
          synchronizer-names-init = synchronizerNamesInit;
          synchronizer-eif = synchronizerEif;
          # Deprecated alias: the EIF is now CID-agnostic (one build for QEMU
          # and Nitro), so this is identical to `synchronizer-eif`.
          synchronizer-eif-nitro = synchronizerEif;
        };

        # `nix run` shorthand and `nix profile install` default.
        apps.enclavia = {
          type = "app";
          program = "${enclaviaCli}/bin/enclavia";
        };
      }
    );
}
