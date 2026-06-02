"""
Test: connection_state_changed=closed must close tube and unregister session.

Reproduces the leak where Commander stopped reporting a tunnel (session removed
from _GLOBAL_TUNNEL_SESSIONS) while the Rust tube kept running because
connection_state_changed=closed didn't call close_tube.

Steps:
  1. Build a loopback WebRTC tunnel → SSH container (port 2222)
  2. Open a real SSH session through it (ssh sleep 60)
  3. Fire connection_state_changed=closed directly into the signal handler
     (simulates ICE timeout / network drop — the path that previously leaked)
  4. Assert the SSH process dies within CLOSE_TIMEOUT_S
  5. Assert the tunnel session is unregistered from _GLOBAL_TUNNEL_SESSIONS
"""
import subprocess
import sys
import threading
import time
import logging

import keeper_pam_connections
from keepercommander.commands.tunnel.port_forward.tunnel_helpers import (
    TunnelSignalHandler,
    register_tunnel_session,
    get_tunnel_session,
    TunnelSession,
    CloseConnectionReasons,
)

SSH_HOST = "127.0.0.1"
SSH_PORT = 2222
SSH_USER = "linuxuser"
SSH_PASS = "alpine"
CLOSE_TIMEOUT_S = 5

TEST_CALLBACK_TOKEN = "TEST_MODE_CALLBACK_TOKEN"
TEST_KSM_CONFIG    = "TEST_MODE_KSM_CONFIG"


def build_loopback_tunnel(registry, peer_map, lock):
    def signal_cb(sig):
        try:
            with lock:
                kind = sig.get("kind")
                tid  = sig.get("tube_id") or sig.get("conversation_id")
                peer = peer_map.get(tid)
            if kind == "ice_candidate" and peer:
                cand = sig.get("candidate")
                if cand:
                    try:
                        registry.add_ice_candidate(peer, cand)
                    except Exception:
                        pass
        except Exception:
            pass

    server_info = registry.create_tube(
        conversation_id="leak-test-server",
        settings={"conversationType": "tunnel", "local_listen_addr": "127.0.0.1:0"},
        trickle_ice=False,
        callback_token=TEST_CALLBACK_TOKEN,
        krelay_server="test.relay.server.com",
        client_version="ms16.5.0",
        ksm_config=TEST_KSM_CONFIG,
        signal_callback=signal_cb,
    )
    server_id = server_info["tube_id"]

    client_info = registry.create_tube(
        conversation_id="leak-test-client",
        settings={
            "conversationType": "tunnel",
            "target_host": SSH_HOST,
            "target_port": str(SSH_PORT),
        },
        trickle_ice=False,
        callback_token=TEST_CALLBACK_TOKEN,
        krelay_server="test.relay.server.com",
        client_version="ms16.5.0",
        ksm_config=TEST_KSM_CONFIG,
        offer=server_info["offer"],
        signal_callback=signal_cb,
    )
    client_id = client_info["tube_id"]

    with lock:
        peer_map[server_id] = client_id
        peer_map[client_id] = server_id

    registry.set_remote_description(server_id, client_info["answer"], is_answer=True)

    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            s = registry.get_tube_status(server_id)
            c = registry.get_tube_status(client_id)
            if s in ("ready", "active") and c in ("ready", "active"):
                break
        except Exception:
            pass
        time.sleep(0.1)
    else:
        print("FAIL: tunnel did not connect within 20s")
        sys.exit(1)

    listen_addr = server_info.get("actual_local_listen_addr")
    return server_id, client_id, listen_addr


def main():
    logging.basicConfig(level=logging.WARNING)

    registry = keeper_pam_connections.PyTubeRegistry()
    peer_map = {}
    lock = threading.Lock()

    print("[1] Building WebRTC loopback tunnel ...")
    server_id, client_id, listen_addr = build_loopback_tunnel(registry, peer_map, lock)
    tunnel_host, tunnel_port = listen_addr.rsplit(":", 1)
    print(f"    Tunnel ready — {listen_addr}")
    time.sleep(0.3)

    print(f"[2] Opening SSH session through tunnel ...")
    ssh_proc = subprocess.Popen(
        [
            "sshpass", f"-p{SSH_PASS}",
            "ssh",
            "-p", tunnel_port,
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ServerAliveInterval=5",
            f"{SSH_USER}@{tunnel_host}",
            "sleep 60",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    time.sleep(2)
    if ssh_proc.poll() is not None:
        print(f"FAIL: SSH exited immediately (rc={ssh_proc.returncode})")
        print(ssh_proc.stderr.read().decode())
        sys.exit(1)
    print(f"    SSH alive (pid={ssh_proc.pid})")

    # Register a minimal tunnel session so the signal handler can look it up
    session = TunnelSession(
        tube_id=server_id,
        conversation_id="leak-test-server",
        gateway_uid="test-gateway",
        symmetric_key=None,
        record_uid="test-record",
        record_title="Test",
        target_host=SSH_HOST,
        target_port=str(SSH_PORT),
        host=tunnel_host,
        port=int(tunnel_port),
    )
    register_tunnel_session(server_id, session)

    # Build the signal handler the same way the tunnel stack does
    handler = TunnelSignalHandler(
        params=None,
        record_uid="test-record",
        gateway_uid="test-gateway",
        symmetric_key=None,
        base64_nonce=None,
        conversation_id="leak-test-server",
        tube_registry=registry,
        tube_id=server_id,
        trickle_ice=False,
    )
    session.signal_handler = handler

    print("[3] Firing connection_state_changed=closed into signal handler ...")
    t_fire = time.time()
    handler.signal_from_rust({
        "kind": "connection_state_changed",
        "tube_id": server_id,
        "data": "closed",
        "conversation_id": "leak-test-server",
    })

    # Check 1: tunnel session must be unregistered
    remaining_session = get_tunnel_session(server_id)
    if remaining_session is not None:
        print(f"FAIL: tunnel session still registered after connection_state_changed=closed")
        ssh_proc.kill()
        sys.exit(2)
    print(f"    Session unregistered ✓")

    # Check 2: SSH process must die within CLOSE_TIMEOUT_S
    try:
        ssh_proc.wait(timeout=CLOSE_TIMEOUT_S)
        elapsed = time.time() - t_fire
        print(f"    SSH exited (rc={ssh_proc.returncode}) {elapsed:.1f}s after signal ✓")
    except subprocess.TimeoutExpired:
        elapsed = time.time() - t_fire
        print(f"\nFAIL: SSH still alive {elapsed:.1f}s after connection_state_changed=closed — tunnel leaked")
        ssh_proc.kill()
        sys.exit(2)

    print("\nPASSED")
    sys.exit(0)


if __name__ == "__main__":
    main()
