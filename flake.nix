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
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay, crane }:
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
          # Beta-tester install entry point. Must stay named `enclavia`
          # so `nix profile install ...#enclavia` matches the binary.
          enclavia = enclaviaCli;
        };

        # `nix run` shorthand and `nix profile install` default.
        apps.enclavia = {
          type = "app";
          program = "${enclaviaCli}/bin/enclavia";
        };
      }
    );
}
