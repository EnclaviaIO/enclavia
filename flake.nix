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
          # The client SDK also compiles to wasm (enclavia-wasm bindings).
          targets = [ "wasm32-unknown-unknown" ];
        });

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        rustSrc = craneLib.cleanCargoSource ./.;

        rustCommonArgs = {
          src = rustSrc;
          strictDeps = true;
          nativeBuildInputs = [ pkgs.pkg-config ];
          # pcsclite: the CLI's default `yubikey` feature (#48) links
          # libpcsclite (PIV over PC/SC) via the pcsc-sys crate.
          buildInputs = [ pkgs.openssl pkgs.pcsclite ];
        };

        cargoArtifacts = craneLib.buildDepsOnly rustCommonArgs;

        individualCrateArgs = rustCommonArgs // {
          inherit cargoArtifacts;
          inherit (craneLib.crateNameFromCargoToml { src = rustSrc; }) version;
          doCheck = false;
        };

        # --- static musl builds for the in-enclave binaries -------------
        #
        # Everything that ships inside an EIF is built as a fully static
        # x86_64-unknown-linux-musl binary. The point is initramfs size:
        # a glibc-dynamic binary drags the whole glibc + libgcc closure
        # (~43 MiB uncompressed, including i18n locale data) into the
        # measured image via its /nix/store RPATH references. The
        # in-enclave crates are pure Rust (TLS is rustls/ring, no
        # openssl/pcsclite -- those belong to the native CLI), so the
        # musl build only needs a musl C compiler for ring's C sources.
        # Derived from the host platform: the in-enclave binaries build on
        # x86_64 (customer enclaves) AND aarch64 (the Graviton
        # synchronizer EIF), each targeting its own musl triple.
        muslTarget = "${pkgs.stdenv.hostPlatform.parsed.cpu.name}-unknown-linux-musl";
        muslTargetEnv = builtins.replaceStrings [ "-" ] [ "_" ] muslTarget;
        muslCc = pkgs.pkgsStatic.stdenv.cc;
        rustToolchainMusl = pkgs: (pkgs.rust-bin.stable."1.88.0".default.override {
          targets = [ muslTarget ];
        });
        craneLibMusl = (crane.mkLib pkgs).overrideToolchain rustToolchainMusl;

        muslCommonArgs = {
          src = rustSrc;
          strictDeps = true;
          CARGO_BUILD_TARGET = muslTarget;
          "CC_${muslTargetEnv}" = "${muslCc}/bin/${muslCc.targetPrefix}cc";
          "CARGO_TARGET_${pkgs.lib.toUpper muslTargetEnv}_LINKER" =
            "${muslCc}/bin/${muslCc.targetPrefix}cc";
        };

        # One deps-only build shared by every binary that ships in a
        # CUSTOMER enclave. Scoped to those packages: the workspace also
        # carries the CLI, whose pcsc-sys/openssl-sys deps neither build
        # on static musl nor belong in an enclave.
        cargoArtifactsMusl = craneLibMusl.buildDepsOnly (muslCommonArgs // {
          pname = "enclavia-in-enclave-musl";
          cargoExtraArgs = pkgs.lib.concatStringsSep " " [
            "-p enclavia-server"
            "-p enclavia-crypto"
            "-p enclavia-egress"
            "-p enclavia-secrets-init"
            "-p enclavia-chain-init"
            "-p nbd-client"
          ];
        });

        # Separate deps-only build for the synchronizer EIF's binaries,
        # kept out of the customer set: someone reproducing a customer
        # enclave build has to compile every binary baked into that
        # image anyway, but the synchronizer is a different image, so
        # its (raft-heavy) dependency graph should not be a build input
        # of customer reproductions.
        cargoArtifactsMuslSync = craneLibMusl.buildDepsOnly (muslCommonArgs // {
          pname = "enclavia-synchronizer-musl";
          cargoExtraArgs = pkgs.lib.concatStringsSep " " [
            "-p synchronizer"
            "-p synchronizer-names-init"
            "--features synchronizer/qemu,synchronizer/raft"
          ];
        });

        individualMuslCrateArgs = muslCommonArgs // {
          cargoArtifacts = cargoArtifactsMusl;
          inherit (craneLibMusl.crateNameFromCargoToml { src = rustSrc; }) version;
          doCheck = false;
        };

        individualMuslSyncCrateArgs = individualMuslCrateArgs // {
          cargoArtifacts = cargoArtifactsMuslSync;
        };

        nbdClient = craneLibMusl.buildPackage (
          individualMuslCrateArgs
          // {
            pname = "nbd-client";
            cargoExtraArgs = "-p nbd-client";
          }
        );

        enclaviaEgress = craneLibMusl.buildPackage (
          individualMuslCrateArgs
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

        enclaviaCrypto = craneLibMusl.buildPackage (
          individualMuslCrateArgs
          // {
            pname = "enclavia-crypto";
            cargoExtraArgs = "-p enclavia-crypto";
          }
        );

        enclaviaServer = craneLibMusl.buildPackage (
          individualMuslCrateArgs
          // {
            pname = "enclavia-server";
            cargoExtraArgs = "-p enclavia-server";
          }
        );

        enclaviaSecretsInit = craneLibMusl.buildPackage (
          individualMuslCrateArgs
          // {
            pname = "enclavia-secrets-init";
            cargoExtraArgs = "-p enclavia-secrets-init";
          }
        );

        enclaviaChainInit = craneLibMusl.buildPackage (
          individualMuslCrateArgs
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
        synchronizer = craneLibMusl.buildPackage (
          individualMuslSyncCrateArgs
          // {
            pname = "enclavia-synchronizer";
            cargoExtraArgs = "-p synchronizer --features qemu,raft";
          }
        );

        # In-enclave runtime identity fetcher (vsock 5011 -> host names
        # responder). Keeps MESH_SELF_NAME / MESH_PEERS out of the
        # measured image and cmdline so the three nodes share one PCR set.
        synchronizerNamesInit = craneLibMusl.buildPackage (
          individualMuslSyncCrateArgs
          // {
            pname = "synchronizer-names-init";
            cargoExtraArgs = "-p synchronizer-names-init";
          }
        );

        # --- enclavia-wasm: the client SDK compiled to wasm --------------
        #
        # ring's C sources must be compiled by a wasm-capable clang; without
        # one, cargo SILENTLY emits the EC math as unresolved `env` imports
        # and the module only fails at instantiation. The unwrapped clang
        # (no glibc wrapper flags) targets wasm natively, but needs its own
        # builtin headers (stddef.h & co) put back on the include path.
        clangUnwrapped = pkgs.llvmPackages.clang-unwrapped;
        wasmRingEnv = {
          CC_wasm32_unknown_unknown = "${clangUnwrapped}/bin/clang";
          CFLAGS_wasm32_unknown_unknown =
            "-I${pkgs.lib.getLib clangUnwrapped}/lib/clang/${pkgs.lib.versions.major clangUnwrapped.version}/include";
        };

        # Scoped to `-p enclavia-wasm`, so only the SDK subtree is built for
        # wasm32 (no openssl/pcsclite — those belong to the native CLI).
        wasmCommonArgs = rustCommonArgs // wasmRingEnv // {
          pname = "enclavia-wasm";
          version = "0.1.0";
          cargoExtraArgs = "-p enclavia-wasm";
          CARGO_BUILD_TARGET = "wasm32-unknown-unknown";
          doCheck = false;
          buildInputs = [ ];
        };

        cargoArtifactsWasm = craneLib.buildDepsOnly wasmCommonArgs;

        # `nix build .#enclavia-wasm` -> $out with the wasm-bindgen output
        # (enclavia_wasm.js + .d.ts + the wasm-opt'd .wasm), ready to publish
        # or vendor. wasm-bindgen-cli's version must equal the crate's pinned
        # `wasm-bindgen` (the ABI schema must match) — both currently 0.2.121,
        # via nixpkgs and enclavia-wasm/Cargo.toml respectively.
        enclaviaWasm = craneLib.buildPackage (wasmCommonArgs // {
          cargoArtifacts = cargoArtifactsWasm;
          nativeBuildInputs = rustCommonArgs.nativeBuildInputs ++ [
            pkgs.wasm-bindgen-cli
            pkgs.binaryen
          ];
          installPhaseCommand = ''
            mkdir -p $out
            wasm-bindgen --target web --out-dir $out \
              target/wasm32-unknown-unknown/release/enclavia_wasm.wasm
            wasm-opt -Os $out/enclavia_wasm_bg.wasm -o $out/enclavia_wasm_bg.wasm
          '';
        });

        # The publish-ready npm package: the reproducible wasm build plus
        # package.json and README. `npm publish result/` (or `npm pack`) from
        # the output. Kept as a separate derivation so the artifact build
        # doesn't rebuild when only packaging metadata changes.
        enclaviaWasmNpm = pkgs.runCommand "enclavia-client-wasm-npm" { } ''
          mkdir -p $out
          cp ${enclaviaWasm}/* $out/
          cp ${./enclavia-wasm/npm/package.json} $out/package.json
          cp ${./enclavia-wasm/README.md} $out/README.md
        '';

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
        devShells.default = pkgs.mkShell ({
          buildInputs = [
            (rustToolchain pkgs)  # includes the wasm32-unknown-unknown target
            pkgs.pkg-config
            pkgs.openssl
            # For the CLI's default `yubikey` feature (#48).
            pkgs.pcsclite
            # wasm client (enclavia-wasm): bindgen glue + wasm-opt. The clang
            # that compiles ring's C for wasm32 is injected via the CC_/CFLAGS_
            # env vars below, so `cargo build --target wasm32-unknown-unknown`
            # just works in this shell.
            pkgs.wasm-bindgen-cli
            pkgs.binaryen
          ];
        } // wasmRingEnv);

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

          # The client SDK as a wasm library (wasm-bindgen output, ready to
          # publish/vendor). Reproducible: two builds yield the same store path.
          enclavia-wasm = enclaviaWasm;
          # The same, assembled as the @enclavia/client-wasm npm package:
          # `nix build .#enclavia-wasm-npm && npm publish result/`.
          enclavia-wasm-npm = enclaviaWasmNpm;

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
