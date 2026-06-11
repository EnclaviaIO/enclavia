#!/bin/sh
#
# Synchronizer EIF init script.
#
# Runs inside the chroot the patched init sets up, as the EIF entrypoint
# (/bin/enclave-init). Unlike the builder's customer init.sh, this EIF
# has no OCI bundle, no crun, no enclavia-server: the synchronizer IS the
# whole in-enclave payload.
#
# Boot steps:
#   1. Bring up loopback (harmless; the synchronizer only uses vsock, but
#      keeps parity with the other enclaves and costs nothing).
#   2. Mount /dev (devtmpfs) so /dev/nsm from the in-tree NSM driver is
#      present for self-attestation, and /proc for diagnostics.
#   3. Fetch this node's identity (MESH_SELF_NAME + MESH_PEERS) from the
#      host over the UNMEASURED vsock side-channel (port 5011) via
#      synchronizer-names-init, and source it. Identity MUST NOT be baked
#      into the image or cmdline: all three nodes run one identical EIF so
#      their PCR0/1/2 match and the self-PCR mesh allowlist admits each
#      other.
#   4. exec the synchronizer. It binds the customer RPC vsock listener
#      (5010), the mesh bootstrap listener (5008), dials mesh-host
#      (host CID 2:5009) for outbound peer traffic, derives its self-PCR
#      digest from /dev/nsm, and joins/forms the Raft cluster.

set -e

echo "synchronizer-init: starting"

# 1 + 2. Filesystems and loopback.
/bin/mkdir -p /dev /proc
/bin/mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
/bin/mount -t proc proc /proc 2>/dev/null || true
/bin/ip link set lo up 2>/dev/null || true
/bin/ip addr add 127.0.0.1/8 dev lo 2>/dev/null || true

if [ -c /dev/nsm ]; then
    echo "synchronizer-init: /dev/nsm present"
else
    echo "synchronizer-init: WARNING /dev/nsm missing; self-attestation will fail" >&2
fi

# 3. Runtime identity over the unmeasured vsock side-channel.
MESH_ENV_FILE=/tmp/mesh-env
echo "synchronizer-init: fetching identity from host vsock 5011"
/bin/synchronizer-names-init "$MESH_ENV_FILE"

# Export every KEY=value line the host served. Lines are trusted UTF-8
# from our own launcher; we only accept the two keys we expect.
if [ -f "$MESH_ENV_FILE" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            MESH_SELF_NAME=*) export MESH_SELF_NAME="${line#MESH_SELF_NAME=}" ;;
            MESH_PEERS=*) export MESH_PEERS="${line#MESH_PEERS=}" ;;
        esac
    done < "$MESH_ENV_FILE"
fi

echo "synchronizer-init: MESH_SELF_NAME=${MESH_SELF_NAME} MESH_PEERS=${MESH_PEERS}"

# 4. Hand off to the synchronizer. RUST_LOG can be overridden by the
#    launcher via the kernel cmdline-derived /env, but we set a useful
#    default here so the serial log shows mesh + raft progress.
export RUST_LOG="${RUST_LOG:-info,synchronizer=debug,openraft=info}"
echo "synchronizer-init: exec enclavia-synchronizer"
exec /bin/enclavia-synchronizer
