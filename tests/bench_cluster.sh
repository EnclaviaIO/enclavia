#!/usr/bin/env bash
#
# Long-lived 3-node synchronizer BENCH cluster (hetzner-beta perf work).
#
# Adapted from run_e2e_synchronizer.sh, but: no build step (artifacts are
# passed in), no teardown trap (the cluster lives until `stop`), and a
# node table chosen to NEVER collide with the deployed beta cluster
# (CIDs 60-62, TCP 39201-39203), the CI e2e (CIDs 90-92, TCP
# 39001-39003), or any live listener on the box.
#
#   node-a: CID 95, mesh inbound TCP 39301
#   node-b: CID 96, mesh inbound TCP 39302
#   node-c: CID 97, mesh inbound TCP 39303
#
# Usage:
#   bench_cluster.sh start   # boots vhost/heartbeat/names/mesh-host/qemu x3
#   bench_cluster.sh wait    # blocks until all 3 log "committed voter"
#   bench_cluster.sh status  # per-node liveness + last serial lines
#   bench_cluster.sh leader  # grep serial logs for the current leader
#   bench_cluster.sh stop    # kills everything recorded in pids/
#
# Required env (start):
#   EIF        path to image.eif
#   MESH_HOST  path to enclavia-mesh-host binary
#   HEARTBEAT  path to heartbeat.py
#   NAMES      path to names-responder.py
#   PYTHON     python3 interpreter
# Optional:
#   WORK       runtime dir (default /root/sync-bench/run)
#   MEMORY     guest RAM (default 768M)

set -euo pipefail

WORK="${WORK:-/root/sync-bench/run}"
MEMORY="${MEMORY:-768M}"
CMD="${1:-status}"

declare -A CID=( [node-a]=95 [node-b]=96 [node-c]=97 )
declare -A TCP=( [node-a]=39301 [node-b]=39302 [node-c]=39303 )
NODES=(node-a node-b node-c)

ndir() { echo "$WORK/$1"; }

start_node() {
    local name="$1"
    local cid="${CID[$name]}"
    local d; d="$(ndir "$name")"
    local proxy="$d/proxy.sock"
    local vhost="$d/vhost.sock"
    mkdir -p "$d"
    rm -f "$vhost" "$proxy" "$proxy"_9000 "$proxy"_5011 "$proxy"_5009

    echo "--- starting $name (CID $cid, inbound TCP ${TCP[$name]}) ---"

    nice -n 5 vhost-device-vsock \
        --vm "guest-cid=${cid},socket=${vhost},uds-path=${proxy}" \
        >"$d/vhost.log" 2>&1 &
    echo "$!" >> "$d/pids"
    for _ in $(seq 1 50); do [ -S "$vhost" ] && break; sleep 0.1; done
    [ -S "$vhost" ] || { echo "FATAL: vhost socket for $name" >&2; exit 1; }

    nice -n 5 "$PYTHON" "$HEARTBEAT" --uds "${proxy}_9000" >"$d/heartbeat.log" 2>&1 &
    echo "$!" >> "$d/pids"

    local p1 p2
    case "$name" in
        node-a) p1=node-b; p2=node-c ;;
        node-b) p1=node-a; p2=node-c ;;
        node-c) p1=node-a; p2=node-b ;;
    esac

    nice -n 5 "$PYTHON" "$NAMES" "${proxy}_5011" "$name" "$p1,$p2" \
        >"$d/names.log" 2>&1 &
    echo "$!" >> "$d/pids"
    for _ in $(seq 1 50); do [ -S "${proxy}_5011" ] && break; sleep 0.1; done

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
    RUST_LOG="${MESH_HOST_LOG:-info}" nice -n 5 "$MESH_HOST" "$d/mesh-host.json" \
        >"$d/mesh-host.log" 2>&1 &
    echo "$!" >> "$d/pids"

    nice -n 5 qemu-system-x86_64 \
        -M "nitro-enclave,vsock=c,id=bench-${name}" \
        -chardev "socket,id=c,path=${vhost}" \
        -kernel "$EIF" \
        -nographic -m "$MEMORY" -smp 1 --enable-kvm -cpu host \
        </dev/null >"$d/serial.log" 2>&1 &
    echo "$!" >> "$d/pids"
    echo "  $name up (qemu pid $!)"
}

case "$CMD" in
start)
    : "${EIF:?}" "${MESH_HOST:?}" "${HEARTBEAT:?}" "${NAMES:?}" "${PYTHON:?}"
    mkdir -p "$WORK"
    for n in "${NODES[@]}"; do
        if [ -f "$(ndir "$n")/pids" ]; then
            echo "FATAL: $(ndir "$n")/pids exists; run stop first" >&2; exit 1
        fi
    done
    for n in "${NODES[@]}"; do start_node "$n"; done
    echo "started; use '$0 wait' for formation"
    ;;
wait)
    timeout="${CLUSTER_TIMEOUT:-240}"
    deadline=$(( $(date +%s) + timeout ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
        formed=yes
        for n in "${NODES[@]}"; do
            grep -aqi "committed voter" "$(ndir "$n")/serial.log" 2>/dev/null || formed=""
        done
        if [ -n "$formed" ]; then echo "cluster formed (all committed voters)"; exit 0; fi
        sleep 3
    done
    echo "TIMEOUT: cluster did not form in ${timeout}s" >&2
    for n in "${NODES[@]}"; do
        echo "--- $n serial tail ---"; tail -5 "$(ndir "$n")/serial.log" 2>/dev/null
    done
    exit 2
    ;;
status)
    for n in "${NODES[@]}"; do
        d="$(ndir "$n")"
        alive=0; total=0
        if [ -f "$d/pids" ]; then
            while read -r pid; do
                total=$((total+1))
                kill -0 "$pid" 2>/dev/null && alive=$((alive+1))
            done < "$d/pids"
        fi
        echo "$n: $alive/$total procs alive"
        tail -2 "$d/serial.log" 2>/dev/null | sed 's/^/    /'
    done
    ;;
leader)
    for n in "${NODES[@]}"; do
        echo "--- $n ---"
        grep -aEi "leader|vote|term" "$(ndir "$n")/serial.log" 2>/dev/null | tail -3
    done
    ;;
stop)
    for n in "${NODES[@]}"; do
        d="$(ndir "$n")"
        [ -f "$d/pids" ] || continue
        while read -r pid; do
            kill "$pid" 2>/dev/null || true
        done < "$d/pids"
        rm -f "$d/pids"
    done
    sleep 1
    echo "stopped"
    ;;
*)
    echo "usage: $0 start|wait|status|leader|stop" >&2; exit 1
    ;;
esac
