# Dedicated synchronizer EIF.
#
# The synchronizer is the entire in-enclave payload: no customer OCI
# image, no enclavia-server, no crun, no namespace stripping. So instead
# of routing through the builder's OCI pipeline we assemble a minimal EIF
# directly with monzo's `nitroLib.buildEif`, using nitro-util's prebuilt
# kernel/nsm.ko blobs and the builder's patched init for QEMU debug.
#
# This file is parameterized over `synchronizerPkg`, and flake.nix
# instantiates it TWICE (the security boundary lives entirely in which
# binary is baked in; everything else is byte-identical):
#
# * `synchronizer-eif` carries the QEMU/dev binary (skip-cert-chain
#   attestation): for the local QEMU harness ONLY.
# * `synchronizer-eif-nitro` carries the production binary (`enclave`
#   feature, full AWS Nitro CA chain verification): the ONLY image a real
#   Nitro deployment may run. The two images measure different PCR0/1/2,
#   so customer configs' `synchronizer.expected_pcrs` must pin the nitro
#   build's measurements.
#
# Patched init (QEMU debug): the stock Nitro init heartbeats to CID 3
# (the real Nitro parent), but under QEMU `vhost-device-vsock` only
# handles CID 2, so we reuse the builder's `init-patched` (heartbeat to
# CID 2). Same artifact the builder's debug enclaves use.
#
# Identical PCRs across nodes: this EIF carries NO per-node identity. All
# three cluster nodes run this one image, so PCR0/1/2 match and the
# self-PCR mesh allowlist admits each peer. Each node's MESH_SELF_NAME /
# MESH_PEERS is fetched at runtime by `synchronizer-names-init` over an
# unmeasured vsock side-channel (see that crate + nix/synchronizer-init.sh).

{
  pkgs,
  nitroLib,
  synchronizerPkg,
  namesInitPkg,
  # In-enclave clock-sync daemon (nitro-timesync, static build).
  timesyncPkg,
  builderSrc,
  # Derivation/image name. The two instantiations differ only in the baked-in
  # synchronizer binary, so the name is the one thing keeping their store
  # paths human-distinguishable.
  eifName ? "synchronizer-enclave",
}:

let
  arch = "x86_64";
  blobs = nitroLib.blobs.${arch};

  # The init for ALL synchronizer EIFs, built from the builder's vendored
  # Go source (vendorHash = null because the source ships its own vendor/
  # tree). It heartbeats BOTH CID 3 (Nitro parent) and CID 2
  # (vhost-device-vsock host), so a single EIF boots on both QEMU and real
  # Nitro -- never AWS' stock CID-3-only blob init. Same init the builder's
  # enclave.nix uses.
  patchedInit = pkgs.buildGoModule {
    name = "synchronizer-eif-init";
    src = "${builderSrc}/nix/init-patched";
    vendorHash = null;
    env.CGO_ENABLED = 0;
    ldflags = [ "-s" "-w" ];
  };

  initBinary = "${patchedInit}/bin/init";

  # A plain `#!/bin/sh` script, run by the image's own busybox. Not
  # `pkgs.writeShellScript`: its shebang names the BUILD host's bash by
  # store path, and the closure of that path (bash + glibc) would then be
  # packed into the measured image.
  initScript = pkgs.writeTextFile {
    name = "synchronizer-enclave-init";
    text = builtins.readFile ./synchronizer-init.sh;
    executable = true;
  };

  # `readelf -h` spelling of the machine every binary in the image must
  # be built for.
  elfMachine = {
    x86_64 = "Advanced Micro Devices X86-64";
    aarch64 = "AArch64";
  }.${arch};

  rootfs = pkgs.runCommand "synchronizer-rootfs" {
    nativeBuildInputs = [ pkgs.binutils-unwrapped ];
  } ''
    mkdir -p $out/bin $out/dev $out/proc $out/tmp

    # The synchronizer node + its runtime identity fetcher.
    cp ${synchronizerPkg}/bin/enclavia-synchronizer $out/bin/
    cp ${namesInitPkg}/bin/synchronizer-names-init $out/bin/
    # Keeps the wall clock on the Nitro hypervisor time (see
    # nitro-timesync); started by the init script before the node.
    cp ${timesyncPkg}/bin/nitro-timesync $out/bin/

    # Minimal busybox for the init script (sh, mount, mkdir, ip; echo and
    # read are sh builtins).
    cp ${pkgs.pkgsStatic.busybox}/bin/busybox $out/bin/busybox
    ln -s busybox $out/bin/sh
    ln -s busybox $out/bin/mount
    ln -s busybox $out/bin/mkdir
    ln -s busybox $out/bin/ip

    # Init script: must live in the rootfs since the init binary
    # chroots to /rootfs before exec'ing the entrypoint.
    cp ${initScript} $out/bin/enclave-init
    chmod +x $out/bin/enclave-init

    # Gate: every binary that ends up in the image (the rootfs plus the
    # init, which buildEif packs into the system ramdisk) must be a static
    # ELF for the EIF's architecture: right machine, no PT_INTERP, no
    # NEEDED entries. The image has no dynamic loader and no libc, so
    # nothing else could run. The only non-ELF file allowed is the init
    # script, which must run under the image's own /bin/sh.
    fail() { echo "synchronizer-rootfs: $*" >&2; exit 1; }
    check_static_elf() {
      machine=$(readelf -hW "$1" | sed -n 's/^ *Machine: *//p')
      [ "$machine" = "${elfMachine}" ] \
        || fail "$1: machine '$machine', expected '${elfMachine}'"
      if readelf -lW "$1" | grep -q INTERP; then
        fail "$1: has a PT_INTERP program header (not static)"
      fi
      if readelf -dW "$1" | grep -q NEEDED; then
        fail "$1: has NEEDED shared-library entries (not static)"
      fi
      echo "synchronizer-rootfs: $1: static, $machine"
    }
    check_static_elf ${initBinary}
    for f in $out/bin/*; do
      if [ -L "$f" ]; then
        [ "$(readlink "$f")" = busybox ] || fail "$f: unexpected symlink"
      elif readelf -h "$f" >/dev/null 2>&1; then
        check_static_elf "$f"
      elif [ "$f" = "$out/bin/enclave-init" ]; then
        [ "$(head -n 1 "$f")" = "#!/bin/sh" ] \
          || fail "$f: shebang is not #!/bin/sh"
      else
        fail "$f: unexpected non-ELF file"
      fi
    done
    extra=$(find $out -mindepth 1 -not -path "$out/bin/*" -not -type d)
    [ -z "$extra" ] || fail "unexpected files outside /bin: $extra"
  '';
in
nitroLib.buildEif {
  name = eifName;
  kernel = blobs.kernel;
  kernelConfig = blobs.kernelConfig;
  # nitro-util's blob kernel is the AWS-provided one, which predates the
  # in-tree NSM driver (kernel 6.8+), so monzo's init insmods this nsm.ko
  # at boot to surface /dev/nsm.
  nsmKo = blobs.nsmKo;
  copyToRoot = rootfs;
  # The rootfs is self-contained (static binaries and a /bin/sh script,
  # enforced above), so nothing in the image resolves a /nix/store path.
  # Copying its closure would only add a second copy of the rootfs and the
  # whole busybox package under /nix/store.
  copyToRootWithClosure = false;
  entrypoint = "/bin/enclave-init";
  init = initBinary;
}
