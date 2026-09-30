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

    # The builder's source, for the synchronizer EIFs' minimal kernel,
    # its config and the patched init. Source only, not a flake input:
    # the builder flake has an `enclavia` input that points back at this
    # flake. The backend overrides that input with an enclavia source
    # when it builds customer EIFs, and if this flake then had the
    # builder as a flake input, Nix would look for the builder's
    # relative `path:./dummy-*` inputs inside the enclavia source and
    # fail. The kernel is built here from this source with the builder's
    # own nixpkgs pin (`nixpkgs-builder`), the same way the builder's
    # flake.nix builds it (see nix/builder-kernels.nix), so it is the
    # exact derivation the builder builds and CI tests.
    # Pinned by rev (builder master at the merge of EnclaviaIO/builder#76,
    # which added the aarch64 kernel and static aarch64 init). Override
    # during local development with
    # `--override-input builder-src path:../builder`, together with
    # `nixpkgs-builder` if that checkout pins another nixpkgs.
    builder-src = {
      url = "github:EnclaviaIO/builder/efa534b610b4cb3e90d9141831d60966d719090a";
      flake = false;
    };

    # The nixpkgs rev that the builder's flake.lock pins at the
    # `builder-src` rev. The kernel is built with it, not with our
    # nixpkgs. It must move together with `builder-src`: evaluation fails
    # if the two disagree.
    nixpkgs-builder.url = "github:NixOS/nixpkgs/643809054d65fdd466a63e3155b8c498cb483c04";

    # In-enclave clock-sync daemon (keeps CLOCK_REALTIME on the NSM
    # attestation timestamp), baked into the synchronizer EIFs. Pinned by
    # rev. Its inputs are deliberately NOT made to follow ours: the binary
    # is then byte-identical to the one the builder puts in customer EIFs,
    # and its own lock already pins the same toolchain revisions as this
    # flake.
    nitro-timesync.url = "github:EnclaviaIO/nitro-timesync/2486fce026c593bb0512351aa06a0027cf1cbd64";
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane, nitro-util, builder-src, nixpkgs-builder, nitro-timesync }:
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
        # Derived from the host platform, so these builds target the
        # host's own musl triple. The Graviton (aarch64) synchronizer EIF
        # does not use them: its binaries are cross-built from x86_64-linux
        # further below.
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
            "--features synchronizer/qemu,synchronizer/raft"
          ];
        });

        # Deps-only build for the PRODUCTION (real Nitro) synchronizer
        # binary. crane's deps-only artifact is feature-sensitive, and the
        # nitro build differs from the qemu one above exactly in the
        # attestation feature (`enclave` alone = full AWS CA chain; `qemu`
        # layers skip-cert-chain on top), so it needs its own artifacts:
        # sharing the qemu artifacts would let a skip-chain dependency
        # fingerprint leak into the production build graph.
        cargoArtifactsMuslSyncNitro = craneLibMusl.buildDepsOnly (muslCommonArgs // {
          pname = "enclavia-synchronizer-nitro-musl";
          cargoExtraArgs = pkgs.lib.concatStringsSep " " [
            "-p synchronizer"
            "--features synchronizer/enclave,synchronizer/raft"
          ];
        });

        # synchronizer-names-init gets a feature-NEUTRAL artifacts build
        # (it does not depend on the synchronizer crate, let alone its
        # attestation features), so ONE artifact serves both EIFs without
        # dragging a qemu-feature fingerprint into the production build
        # graph.
        cargoArtifactsMuslNamesInit = craneLibMusl.buildDepsOnly (muslCommonArgs // {
          pname = "synchronizer-names-init-musl";
          cargoExtraArgs = "-p synchronizer-names-init";
        });

        individualMuslCrateArgs = muslCommonArgs // {
          cargoArtifacts = cargoArtifactsMusl;
          inherit (craneLibMusl.crateNameFromCargoToml { src = rustSrc; }) version;
          doCheck = false;
        };

        individualMuslSyncCrateArgs = individualMuslCrateArgs // {
          cargoArtifacts = cargoArtifactsMuslSync;
        };

        individualMuslSyncNitroCrateArgs = individualMuslCrateArgs // {
          cargoArtifacts = cargoArtifactsMuslSyncNitro;
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

        # In-enclave synchronizer node binary, QEMU/dev variant
        # (`--features qemu,raft`): vsock customer listener + vsock mesh
        # transport (same as `enclave`) but SKIP-CERT-CHAIN attestation
        # (`DEBUG_MODE = true` in main.rs), which is what QEMU's
        # self-signing NSM emits. DEV/TEST ONLY: this build accepts
        # attestation documents without verifying the AWS Nitro CA chain or
        # the COSE signature, so on real Nitro a malicious host could join
        # the Raft mesh with arbitrary forged documents. Never ship it to
        # production; use `synchronizerNitro` below. `raft` turns on the
        # replicated cluster path (mesh + openraft). One identical binary
        # runs on all three nodes; identity is injected at runtime (see
        # synchronizer-names-init), never baked in, so PCRs stay equal.
        synchronizer = craneLibMusl.buildPackage (
          individualMuslSyncCrateArgs
          // {
            pname = "enclavia-synchronizer";
            cargoExtraArgs = "-p synchronizer --features qemu,raft";
          }
        );

        # PRODUCTION synchronizer node binary (`--features enclave,raft`,
        # NO `qemu`): `DEBUG_MODE = false`, so attestation verification runs
        # the FULL AWS Nitro CA chain + COSE signature check
        # (enclavia-protocol's `parse_and_validate` production path). This is
        # the only binary a real Nitro deployment may run: anything less lets
        # a host join the mesh with a forged document and vote Byzantine
        # anti-rollback state. Same runtime-identity story as the qemu build
        # (nothing per-node baked in), so all three production nodes also
        # share one PCR set — but a DIFFERENT one from the qemu build (the
        # measured payload differs), which is why customer configs'
        # `synchronizer.expected_pcrs` must pin THIS build's measurements.
        # The production EIF carries the aarch64 cross build of it
        # (`synchronizerNitroAarch64` below); this host-arch build stays
        # available as the `synchronizer-nitro` package.
        synchronizerNitro = craneLibMusl.buildPackage (
          individualMuslSyncNitroCrateArgs
          // {
            pname = "enclavia-synchronizer-nitro";
            cargoExtraArgs = "-p synchronizer --features enclave,raft";
          }
        );

        # In-enclave runtime identity fetcher (vsock 5011 -> host names
        # responder). Keeps MESH_SELF_NAME / MESH_PEERS out of the
        # measured image and cmdline so the three nodes share one PCR set.
        # Built from the feature-neutral artifacts (it has no synchronizer
        # feature surface), so the same binary serves the dev and
        # production EIFs.
        synchronizerNamesInit = craneLibMusl.buildPackage (
          individualMuslCrateArgs
          // {
            cargoArtifacts = cargoArtifactsMuslNamesInit;
            pname = "synchronizer-names-init";
            cargoExtraArgs = "-p synchronizer-names-init";
          }
        );

        # In-enclave clock-sync daemon (static musl build from the standalone
        # nitro-timesync flake): keeps CLOCK_REALTIME on the Nitro hypervisor
        # time read from /dev/nsm attestation documents.
        nitroTimesync = nitro-timesync.packages.${system}.nitro-timesync-static;

        # --- aarch64 (Graviton) cross builds ------------------------------
        #
        # The production synchronizer runs on Graviton, so every binary in
        # `synchronizer-eif-nitro` is a static aarch64-unknown-linux-musl
        # binary cross-built on x86_64-linux. The cross build is the
        # canonical one: it is what third parties run to reproduce the
        # production PCRs, on ordinary x86_64 machines. Only used by the
        # x86_64-linux outputs (see the EIF section below).
        aarch64Cross = pkgs.pkgsCross.aarch64-multiplatform;
        muslTargetAarch64 = "aarch64-unknown-linux-musl";
        muslCcAarch64 = aarch64Cross.pkgsStatic.stdenv.cc;
        craneLibMuslAarch64 = (crane.mkLib pkgs).overrideToolchain (p:
          p.rust-bin.stable."1.88.0".default.override {
            targets = [ muslTargetAarch64 ];
          });

        # Cross C compiler and archiver for ring's C sources, and the
        # linker for the final binaries.
        muslCrossArgsAarch64 = {
          strictDeps = true;
          doCheck = false;
          CARGO_BUILD_TARGET = muslTargetAarch64;
          CC_aarch64_unknown_linux_musl = "${muslCcAarch64}/bin/${muslCcAarch64.targetPrefix}cc";
          AR_aarch64_unknown_linux_musl = "${muslCcAarch64.bintools.bintools}/bin/${muslCcAarch64.targetPrefix}ar";
          CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER = "${muslCcAarch64}/bin/${muslCcAarch64.targetPrefix}cc";
        };

        muslCommonArgsAarch64 = muslCrossArgsAarch64 // {
          src = rustSrc;
          inherit (craneLibMuslAarch64.crateNameFromCargoToml { src = rustSrc; }) version;
        };

        # Production synchronizer node (`--features enclave,raft`, see
        # `synchronizerNitro` above), for aarch64. Own deps-only build for
        # the same reason as the x86_64 one: no qemu-feature fingerprint in
        # the production build graph.
        synchronizerNitroAarch64 = craneLibMuslAarch64.buildPackage (muslCommonArgsAarch64 // {
          pname = "enclavia-synchronizer-nitro-aarch64";
          cargoArtifacts = craneLibMuslAarch64.buildDepsOnly (muslCommonArgsAarch64 // {
            pname = "enclavia-synchronizer-nitro-musl-aarch64";
            cargoExtraArgs = "-p synchronizer --features synchronizer/enclave,synchronizer/raft";
          });
          cargoExtraArgs = "-p synchronizer --features enclave,raft";
        });

        synchronizerNamesInitAarch64 = craneLibMuslAarch64.buildPackage (muslCommonArgsAarch64 // {
          pname = "synchronizer-names-init-aarch64";
          cargoArtifacts = craneLibMuslAarch64.buildDepsOnly (muslCommonArgsAarch64 // {
            pname = "synchronizer-names-init-musl-aarch64";
            cargoExtraArgs = "-p synchronizer-names-init";
          });
          cargoExtraArgs = "-p synchronizer-names-init";
        });

        # nitro-timesync's flake only builds for its own host, so the
        # aarch64 binary is cross-built here from the same pinned source,
        # the same way (static musl, same Rust version, no C dependencies).
        # Unlike the x86_64 binary it is not byte-identical to one the
        # builder ships.
        nitroTimesyncSrcAarch64 = craneLibMuslAarch64.cleanCargoSource nitro-timesync;
        nitroTimesyncArgsAarch64 = muslCrossArgsAarch64 // {
          src = nitroTimesyncSrcAarch64;
          pname = "nitro-timesync-aarch64";
          inherit (craneLibMuslAarch64.crateNameFromCargoToml { src = nitroTimesyncSrcAarch64; }) version;
        };
        nitroTimesyncAarch64 = craneLibMuslAarch64.buildPackage (nitroTimesyncArgsAarch64 // {
          cargoArtifacts = craneLibMuslAarch64.buildDepsOnly nitroTimesyncArgsAarch64;
        });

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

        # --- Dedicated synchronizer EIFs --------------------------------
        #
        # NOT the builder's OCI pipeline: the synchronizer is the entire
        # in-enclave payload, so we assemble a minimal EIF directly with
        # monzo's nitroLib.buildEif, from the builder's minimal kernel and
        # its patched (CID 2 + CID 3 heartbeat) init. See
        # nix/synchronizer-eif.nix for the rationale.
        #
        # The builder only builds on x86_64-linux, which is also the one
        # host the synchronizer EIFs are defined for: that is the build
        # third parties reproduce the PCRs with.
        nitroLib = nitro-util.lib.${system};

        # nixpkgs as the builder's flake.nix imports it, at the rev the
        # builder's flake.lock pins. `nixpkgs-builder` must be that rev.
        builderLock = builtins.fromJSON (builtins.readFile "${builder-src}/flake.lock");
        builderNixpkgsRev = builderLock.nodes.${builderLock.nodes.root.inputs.nixpkgs}.locked.rev;
        builderNixpkgs =
          if (nixpkgs-builder.rev or builderNixpkgsRev) == builderNixpkgsRev
          then import nixpkgs-builder { system = "x86_64-linux"; }
          else throw "nixpkgs-builder is at ${nixpkgs-builder.rev}, but builder-src pins nixpkgs ${builderNixpkgsRev}; move them together";

        # The builder's minimal kernels (x86_64 and the aarch64 cross
        # build) and its x86_64 and static aarch64 inits, built from its
        # source and nixpkgs.
        builderKernels = import ./nix/builder-kernels.nix {
          pkgs = builderNixpkgs;
          builderSrc = builder-src;
        };

        # Two REAL, distinct EIFs, one per synchronizer binary variant
        # above, with separate PCRs. They are not interchangeable, and the
        # difference is the whole security boundary:
        #
        # * `synchronizer-eif` (qemu binary, x86_64): DEV/TEST ONLY, for the
        #   local QEMU cluster (QEMU's nitro-enclave machine is x86_64-only).
        #   Attestation verification skips the AWS Nitro CA chain / COSE
        #   signature so it can run under QEMU's self-signing NSM. On real
        #   Nitro it would accept forged attestation documents, letting a
        #   malicious host join the Raft mesh and fabricate committed
        #   anti-rollback state.
        # * `synchronizer-eif-nitro` (enclave binary, aarch64): PRODUCTION,
        #   for Graviton Nitro Enclaves. Full AWS Nitro CA chain
        #   verification; this is the only EIF a real deployment may run.
        #
        # The two images measure DIFFERENTLY (different binaries and
        # architectures -> different PCR0/1/2), so customer configs'
        # `synchronizer.expected_pcrs` must pin the NITRO build's
        # measurements; pinning the dev build's PCRs would re-open the
        # forged-attestation hole above.
        synchronizerEif = pkgs.callPackage ./nix/synchronizer-eif.nix {
          inherit pkgs nitroLib;
          arch = "x86_64";
          # The builder's minimal non-storage kernel.
          kernel = "${builderKernels.kernel}/bzImage";
          kernelConfig = "${builderKernels.kernelConfig}/config";
          init = "${builderKernels.init}/bin/init";
          synchronizerPkg = synchronizer;
          namesInitPkg = synchronizerNamesInit;
          timesyncPkg = nitroTimesync;
          busyboxPkg = pkgs.pkgsStatic.busybox;
        };

        synchronizerEifNitro = pkgs.callPackage ./nix/synchronizer-eif.nix {
          inherit pkgs nitroLib;
          eifName = "synchronizer-enclave-nitro";
          arch = "aarch64";
          # The builder's minimal aarch64 kernel (base profile) and its
          # static aarch64 init, both cross-built on x86_64-linux.
          kernel = "${builderKernels.kernelAarch64}/Image";
          kernelConfig = "${builderKernels.kernelConfigAarch64}/config";
          init = "${builderKernels.initAarch64}/bin/init";
          synchronizerPkg = synchronizerNitroAarch64;
          namesInitPkg = synchronizerNamesInitAarch64;
          timesyncPkg = nitroTimesyncAarch64;
          busyboxPkg = aarch64Cross.pkgsStatic.busybox;
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
            # Runs the wasm npm package's smoke tests (enclavia-wasm/*.mjs);
            # >= 22 for the global WebSocket the bindings use.
            pkgs.nodejs_22
          ];
        } // wasmRingEnv);

        # `enclavia-dart` bindings: Dart SDK for `dart pub get` / `dart run`,
        # which drives Native Assets (`hook/build.dart`), which in turn
        # invokes `native_toolchain_rust`. That package unconditionally
        # shells out to `rustup show active-toolchain` / `rustup toolchain
        # install` against `native/rust-toolchain.toml` — it has no support
        # for an ambient, non-rustup toolchain (like the Nix-provided one
        # `devShells.default` uses), so this shell provides `rustup` itself
        # rather than `rustToolchain`, exactly as a non-Nix contributor
        # following upstream bdk-dart's own setup instructions would. Split
        # out of `devShells.default` because the Dart SDK and a
        # rustup-managed toolchain are a sizeable extra download most
        # contributors (who never touch enclavia-dart) don't need.
        devShells.dart = pkgs.mkShell {
          buildInputs = [
            pkgs.rustup
            pkgs.pkg-config
            pkgs.dart
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

          # The client SDK as a wasm library (wasm-bindgen output, ready to
          # publish/vendor). Reproducible: two builds yield the same store path.
          enclavia-wasm = enclaviaWasm;
          # The same, assembled as the @enclavia/client-wasm npm package:
          # `nix build .#enclavia-wasm-npm && npm publish result/`.
          enclavia-wasm-npm = enclaviaWasmNpm;

          # Synchronizer node binaries + their runtime identity fetcher,
          # plus the dedicated EIFs that wrap them. `synchronizer` /
          # `synchronizer-eif` are the QEMU/dev variants (skip-cert-chain
          # attestation; never for production). `synchronizer-nitro` /
          # `synchronizer-eif-nitro` are the PRODUCTION real-Nitro variants
          # (full AWS CA chain): the production mesh only admits peers
          # running this image, and customer configs' expected PCRs must
          # pin ITS measurements.
          synchronizer = synchronizer;
          synchronizer-nitro = synchronizerNitro;
          synchronizer-names-init = synchronizerNamesInit;
        } // pkgs.lib.optionalAttrs (system == "x86_64-linux") {
          # Built on the builder's kernels, which build on x86_64-linux
          # only (see above).
          # `synchronizer-eif` is x86_64 (QEMU dev cluster);
          # `synchronizer-eif-nitro` is aarch64 (Graviton production),
          # cross-built here, as are the aarch64 binaries it carries.
          synchronizer-eif = synchronizerEif;
          synchronizer-eif-nitro = synchronizerEifNitro;
          synchronizer-nitro-aarch64 = synchronizerNitroAarch64;
          synchronizer-names-init-aarch64 = synchronizerNamesInitAarch64;
          nitro-timesync-aarch64 = nitroTimesyncAarch64;
        };

        # `nix run` shorthand and `nix profile install` default.
        apps.enclavia = {
          type = "app";
          program = "${enclaviaCli}/bin/enclavia";
        };
      }
    );
}
