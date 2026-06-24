# Dedicated synchronizer EIF.
#
# The synchronizer is the entire in-enclave payload: no customer OCI
# image, no enclavia-server, no crun, no namespace stripping. So instead
# of routing through the builder's OCI pipeline we assemble a minimal EIF
# directly with monzo's `nitroLib.buildEif`, using nitro-util's prebuilt
# kernel/nsm.ko blobs and the builder's patched init for QEMU debug.
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
  builderSrc,
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

  initScript = pkgs.writeShellScript "synchronizer-enclave-init"
    (builtins.readFile ./synchronizer-init.sh);

  rootfs = pkgs.runCommand "synchronizer-rootfs" {} ''
    mkdir -p $out/bin $out/dev $out/proc $out/tmp

    # The synchronizer node + its runtime identity fetcher.
    cp ${synchronizerPkg}/bin/enclavia-synchronizer $out/bin/
    cp ${namesInitPkg}/bin/synchronizer-names-init $out/bin/

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
  '';
in
nitroLib.buildEif {
  name = "synchronizer-enclave";
  kernel = blobs.kernel;
  kernelConfig = blobs.kernelConfig;
  # nitro-util's blob kernel is the AWS-provided one, which predates the
  # in-tree NSM driver (kernel 6.8+), so monzo's init insmods this nsm.ko
  # at boot to surface /dev/nsm.
  nsmKo = blobs.nsmKo;
  copyToRoot = rootfs;
  entrypoint = "/bin/enclave-init";
  init = initBinary;
}
