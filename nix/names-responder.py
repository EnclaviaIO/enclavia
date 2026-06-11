#!/usr/bin/env python3
"""
Host-side names responder for the synchronizer EIF (QEMU debug).

One instance per guest. The guest's in-enclave `synchronizer-names-init`
dials host CID 2 vsock port 5011; under QEMU's `vhost-device-vsock` UDS
mode that surfaces on the host as a connection to `<proxy>_5011`, so we
LISTEN on that Unix socket and serve this one guest its identity:

    MESH_SELF_NAME=<name>
    MESH_PEERS=<comma-separated peer names>

Wire format (mirrors secrets-host): a 4-byte big-endian length prefix
followed by the payload. We do NOT shutdown(WRITE); we block on the
guest's one-byte ACK before closing, so the FIN never races the guest's
read at the vhost-device-vsock UDS->virtio bridge (which on the older AWS
guest kernel coalesces a small payload + FIN into one frame and surfaces
as ENOTCONN). Long-lived: loops to serve a possible reconnect (e.g. a
node restart re-fetches its identity).

This is the host analogue of `secrets-host`, kept as a tiny standalone
script because the host side is not transport-constrained (busybox `nc`
in the guest cannot speak vsock, which is why the GUEST side is a Rust
client; the host can use anything). Usage:

    names-responder.py <listen-uds-path> <self-name> <peer1,peer2,...>
"""

import os
import socket
import sys


def main():
    if len(sys.argv) != 4:
        print(
            "usage: names-responder.py <listen-uds-path> <self-name> <peers-csv>",
            file=sys.stderr,
        )
        sys.exit(2)

    listen_path, self_name, peers_csv = sys.argv[1], sys.argv[2], sys.argv[3]
    body = f"MESH_SELF_NAME={self_name}\nMESH_PEERS={peers_csv}\n".encode()
    # 4-byte BE length prefix + body (see module docstring).
    payload = len(body).to_bytes(4, "big") + body

    try:
        os.unlink(listen_path)
    except FileNotFoundError:
        pass

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(listen_path)
    srv.listen(8)
    print(
        f"names-responder: listening on {listen_path} "
        f"(self={self_name} peers={peers_csv})",
        flush=True,
    )

    while True:
        conn, _ = srv.accept()
        try:
            conn.sendall(payload)
            # Block on the guest's ACK byte before closing, so our FIN
            # never races the guest's read at the bridge. Do NOT
            # shutdown(WRITE) first.
            try:
                conn.settimeout(30.0)
                conn.recv(1)
            except (socket.timeout, OSError):
                pass
            print(f"names-responder: served identity to {self_name}", flush=True)
        finally:
            conn.close()


if __name__ == "__main__":
    main()
