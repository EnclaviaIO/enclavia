#!/usr/bin/env bash
#
# End-to-end: a REAL 3-node synchronizer cluster in QEMU.
#
# Builds ONE synchronizer EIF (identical PCRs on every node), boots three
# QEMU nitro-enclave guests with distinct CIDs and names (node-a/b/c),
# bridges their mesh over `mesh-host` instances wired into a triangle of
# inter-host TCP links, lets them mutually attest + form a Raft cluster,
# then drives a customer Pin on one node and a Get on ANOTHER through the
# cluster (forwarding + linearizable read).
#
# Identity injection: each guest fetches its MESH_SELF_NAME / MESH_PEERS
# at runtime from a per-guest host "names responder" over an UNMEASURED
# vsock side-channel (port 5011). Nothing per-node is baked into the
# image or kernel cmdline, so PCR0/1/2 are identical across the three and
# the self-PCR mesh allowlist admits each peer.
#
# Requirements (all in the enclavia-crates dev shell): nix, qemu,
# vhost-device-vsock, python3. /dev/kvm strongly recommended.
#
# Layout (all per-node sockets/logs under $WORK):
#   node-a: CID 90, proxy <WORK>/a/proxy.sock, mesh inbound TCP 39001
#   node-b: CID 91, proxy <WORK>/b/proxy.sock, mesh inbound TCP 39002
#   node-c: CID 92, proxy <WORK>/c/proxy.sock, mesh inbound TCP 39003
#   customer RPC port 5010, mesh bootstrap 5008, mesh-host outbound 5009.
#
# Env knobs:
#   WORK            scratch dir (default: mktemp under /tmp)
#   ENCLAVIA_DIR    path to the enclavia checkout (this branch). Default:
#                   resolved from this script's location.
#   CRATES_DIR      path to the enclavia-crates checkout (mesh-host). Default ../enclavia-crates
#   BUILDER_DIR     path to the builder checkout (init-patched + blobs). Default ../builder
#   MEMORY          guest RAM (default 768M)
#   CLUSTER_TIMEOUT seconds to wait for leader election (default 180)
#   KEEP            if set, do not tear down at the end (debugging)

set -euo pipefail

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENCLAVIA_DIR="${ENCLAVIA_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
CRATES_DIR="${CRATES_DIR:-$(cd "$ENCLAVIA_DIR/../enclavia-crates" && pwd 2>/dev/null || echo "")}"
BUILDER_DIR="${BUILDER_DIR:-$(cd "$ENCLAVIA_DIR/../builder" && pwd 2>/dev/null || echo "")}"

MEMORY="${MEMORY:-768M}"
CLUSTER_TIMEOUT="${CLUSTER_TIMEOUT:-180}"

NAMES_SCRIPT="$ENCLAVIA_DIR/nix/names-responder.py"
HEARTBEAT_SCRIPT="${HEARTBEAT_SCRIPT:-$BUILDER_DIR/nix/heartbeat.py}"

if [ -z "$CRATES_DIR" ] || [ ! -d "$CRATES_DIR" ]; then
    echo "FATAL: enclavia-crates checkout not found (set CRATES_DIR)" >&2
    exit 1
fi
if [ -z "$BUILDER_DIR" ] || [ ! -d "$BUILDER_DIR" ]; then
    echo "FATAL: builder checkout not found (set BUILDER_DIR)" >&2
    exit 1
fi

WORK="${WORK:-$(mktemp -d /tmp/sync-e2e.XXXXXX)}"
mkdir -p "$WORK"
echo "=== synchronizer 3-node e2e ==="
echo "  enclavia : $ENCLAVIA_DIR"
echo "  crates   : $CRATES_DIR"
echo "  builder  : $BUILDER_DIR"
echo "  work     : $WORK"
echo "  memory   : $MEMORY   kvm: $([ -e /dev/kvm ] && echo yes || echo no)"

PIDS=()
cleanup() {
    echo ""
    echo "=== teardown ==="
    for pid in "${PIDS[@]:-}"; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done
    # QEMU children sometimes outlive the wrapper; nuke by name within WORK.
    pkill -f "qemu-system-x86_64.*$WORK" 2>/dev/null || true
    pkill -f "vhost-device-vsock.*$WORK" 2>/dev/null || true
    pkill -f "names-responder.py $WORK" 2>/dev/null || true
    sleep 1
    if [ -z "${KEEP:-}" ]; then
        rm -rf "$WORK"
        echo "  removed $WORK"
    else
        echo "  KEEP set; left $WORK in place"
    fi
}
trap cleanup EXIT INT TERM

wait_for_socket() {
    local path="$1" tries="${2:-100}"
    for _ in $(seq 1 "$tries"); do
        [ -S "$path" ] && return 0
        sleep 0.1
    done
    return 1
}

# ---------------------------------------------------------------------------
# 1. Build everything ONCE.
# ---------------------------------------------------------------------------
echo ""
echo "=== build (one EIF, identical PCRs) ==="

echo "  building synchronizer EIF..."
nice nix build "path:$ENCLAVIA_DIR#synchronizer-eif" \
    --override-input builder-src "path:$BUILDER_DIR" \
    --out-link "$WORK/eif" --print-build-logs
EIF="$WORK/eif/image.eif"
[ -f "$EIF" ] || { echo "FATAL: EIF not produced at $EIF" >&2; ls -la "$WORK/eif" >&2; exit 1; }
echo "  EIF: $EIF"

# Record the PCRs the build measured (same for all three nodes). The EIF
# build prints a PCR JSON next to the image in newer nitro-util; if absent
# we just note that all nodes share this single artifact.
if [ -f "$WORK/eif/pcr.json" ]; then
    echo "  PCRs (single image, shared by all nodes):"
    cat "$WORK/eif/pcr.json"
fi

echo "  building mesh-host (debug)..."
nice nix build "path:$CRATES_DIR#mesh-host-debug" --out-link "$WORK/mesh-host" --print-build-logs
MESH_HOST="$WORK/mesh-host/bin/enclavia-mesh-host"
[ -x "$MESH_HOST" ] || { echo "FATAL: mesh-host not built" >&2; exit 1; }

echo "  building mesh_client example..."
( cd "$ENCLAVIA_DIR" && nice cargo build --release --example mesh_client -p synchronizer --features qemu,raft )
CLIENT="$ENCLAVIA_DIR/target/release/examples/mesh_client"
[ -x "$CLIENT" ] || { echo "FATAL: mesh_client not built" >&2; exit 1; }
echo "  client: $CLIENT"

# ---------------------------------------------------------------------------
# 2. Per-node plumbing.
# ---------------------------------------------------------------------------
# Node table: name cid inbound-tcp-port letter
declare -A CID=( [node-a]=90 [node-b]=91 [node-c]=92 )
declare -A TCP=( [node-a]=39001 [node-b]=39002 [node-c]=39003 )
declare -A DIR=( [node-a]="$WORK/a" [node-b]="$WORK/b" [node-c]="$WORK/c" )
declare -A PEERS=( [node-a]="node-b,node-c" [node-b]="node-a,node-c" [node-c]="node-a,node-b" )

start_node() {
    local name="$1"
    local cid="${CID[$name]}"
    local d="${DIR[$name]}"
    local proxy="$d/proxy.sock"
    local vhost="$d/vhost.sock"
    local serial="$d/serial.log"
    mkdir -p "$d"

    echo ""
    echo "--- starting $name (CID $cid, inbound TCP ${TCP[$name]}) ---"

    # vhost-device-vsock (UDS mode): guest CID 2:PORT -> ${proxy}_PORT.
    vhost-device-vsock --vm "guest-cid=${cid},socket=${vhost},uds-path=${proxy}" \
        >"$d/vhost.log" 2>&1 &
    PIDS+=("$!")
    wait_for_socket "$vhost" 50 || { echo "FATAL: vhost socket for $name" >&2; exit 1; }

    # Heartbeat responder (guest init -> CID 2:9000 -> ${proxy}_9000).
    python3 "$HEARTBEAT_SCRIPT" --uds "${proxy}_9000" >"$d/heartbeat.log" 2>&1 &
    PIDS+=("$!")

    # Names responder (guest -> CID 2:5011 -> ${proxy}_5011): serves this
    # guest's identity. Long-lived (survives a node restart re-fetch).
    python3 "$NAMES_SCRIPT" "${proxy}_5011" "$name" "${PEERS[$name]}" \
        >"$d/names.log" 2>&1 &
    PIDS+=("$!")
    wait_for_socket "${proxy}_5011" 50 || { echo "FATAL: names socket for $name" >&2; exit 1; }

    # mesh-host config: OUTBOUND listens on ${proxy}_5009 (guest dials host
    # 5009); INBOUND TCP on 127.0.0.1:${TCP}; dials this guest's bootstrap
    # 5008 via proxy connect; peers map the OTHER two names to their
    # mesh-hosts' inbound TCP.
    local p1 p2
    case "$name" in
        node-a) p1=node-b; p2=node-c ;;
        node-b) p1=node-a; p2=node-c ;;
        node-c) p1=node-a; p2=node-b ;;
    esac
    cat > "$d/mesh-host.json" <<EOF
{
  "inbound_listen": "127.0.0.1:${TCP[$name]}",
  "peers": {
    "$p1": "127.0.0.1:${TCP[$p1]}",
    "$p2": "127.0.0.1:${TCP[$p2]}"
  },
  "transport": { "proxy_base": "$proxy" }
}
EOF
    RUST_LOG="${MESH_HOST_LOG:-info}" "$MESH_HOST" "$d/mesh-host.json" \
        >"$d/mesh-host.log" 2>&1 &
    PIDS+=("$!")

    # QEMU nitro-enclave with the shared EIF.
    local qemu_args=(
        -M "nitro-enclave,vsock=c,id=sync-${name}"
        -chardev "socket,id=c,path=${vhost}"
        -kernel "$EIF"
        -nographic
        -m "$MEMORY"
        -smp 1
    )
    if [ -e /dev/kvm ]; then
        qemu_args+=(--enable-kvm -cpu host)
    else
        qemu_args+=(-cpu max)
    fi
    nice qemu-system-x86_64 "${qemu_args[@]}" </dev/null >"$serial" 2>&1 &
    PIDS+=("$!")
    echo "  $name QEMU pid $! -> serial $serial"
}

start_node node-a
start_node node-b
start_node node-c

# ---------------------------------------------------------------------------
# 3. Wait for the cluster to form (leader elected + voters joined).
# ---------------------------------------------------------------------------
echo ""
echo "=== waiting for cluster formation (up to ${CLUSTER_TIMEOUT}s) ==="
LEADER=""
deadline=$(( $(date +%s) + CLUSTER_TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
    # Look for cluster-formation evidence across the three serial logs:
    # the synchronizer logs "leader elected" (RaftHandle metrics wait),
    # "initialized a fresh cluster", and "committed voter; discovery
    # complete".
    for name in node-a node-b node-c; do
        s="${DIR[$name]}/serial.log"
        if grep -Eqi "leader elected|initialized a fresh cluster|committed voter" "$s" 2>/dev/null; then
            LEADER="$name"
        fi
    done
    if [ -n "$LEADER" ]; then break; fi
    sleep 3
done

echo ""
echo "=== serial-log evidence ==="
for name in node-a node-b node-c; do
    s="${DIR[$name]}/serial.log"
    echo "--- $name attestation / mesh / raft lines ---"
    grep -Ei "self-attestation|self-PCR|/dev/nsm|mesh|attest|admitted|allowlist|peer|leader|term|vote|join|cluster|initialize|election" "$s" 2>/dev/null | tail -40 || true
    echo ""
done

if [ -z "$LEADER" ]; then
    echo "BLOCKER: no Raft leader observed within ${CLUSTER_TIMEOUT}s. Serial tails above." >&2
    echo "Full serial logs under: $WORK/{a,b,c}/serial.log" >&2
    [ -n "${KEEP:-}" ] || echo "(set KEEP=1 to retain logs)"
    exit 2
fi
echo "Observed Raft leader activity (node reporting leadership: $LEADER)"

# ---------------------------------------------------------------------------
# 4. Client round-trip: Pin on node-a, Get on node-b (cross-node).
# ---------------------------------------------------------------------------
echo ""
echo "=== client Pin (node-a) then Get (node-b), same key ==="
SEED=0x42
COMMIT=0xab

echo "--- Pin on node-a ---"
"$CLIENT" "${DIR[node-a]}/proxy.sock" pin "$COMMIT" --port 5010 --seed "$SEED"

echo "--- Get on node-b (forwarded to leader, linearizable) ---"
GET_OUT="$("$CLIENT" "${DIR[node-b]}/proxy.sock" get --port 5010 --seed "$SEED")"
echo "$GET_OUT"

if echo "$GET_OUT" | grep -q "get ok commitment_byte=$COMMIT"; then
    echo ""
    echo "PASS: cross-node Pin/Get round-trip (wrote on node-a, read identical commitment on node-b)"
else
    echo ""
    echo "BLOCKER: cross-node Get did not return the pinned commitment ($COMMIT). Output: $GET_OUT" >&2
    exit 3
fi

# ---------------------------------------------------------------------------
# 5. Optional: restart a node and show it re-joins + serves a Get (#209).
# ---------------------------------------------------------------------------
if [ -n "${TEST_RESTART:-}" ]; then
    echo ""
    echo "=== restart node-c and show re-join + Get ==="
    # Kill node-c's QEMU only (leave its vhost/mesh-host/names alive).
    pkill -f "qemu-system-x86_64.*sync-node-c" 2>/dev/null || true
    sleep 3
    : > "${DIR[node-c]}/serial.log"
    qc=(
        -M "nitro-enclave,vsock=c,id=sync-node-c"
        -chardev "socket,id=c,path=${DIR[node-c]}/vhost.sock"
        -kernel "$EIF" -nographic -m "$MEMORY" -smp 1
    )
    [ -e /dev/kvm ] && qc+=(--enable-kvm -cpu host) || qc+=(-cpu max)
    nice qemu-system-x86_64 "${qc[@]}" </dev/null >"${DIR[node-c]}/serial.log" 2>&1 &
    PIDS+=("$!")
    echo "  node-c relaunched (pid $!); waiting for re-join..."
    sleep 30
    grep -Ei "join|hydrat|snapshot|voter|cluster" "${DIR[node-c]}/serial.log" | tail -20 || true
    echo "--- Get on node-c after restart ---"
    "$CLIENT" "${DIR[node-c]}/proxy.sock" get --port 5010 --seed "$SEED" || \
        echo "(node-c Get failed; see ${DIR[node-c]}/serial.log)"
fi

echo ""
echo "=== DONE ==="
