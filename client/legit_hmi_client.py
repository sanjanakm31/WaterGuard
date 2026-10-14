"""
client/legit_hmi_client.py

A legitimate Human-Machine-Interface (HMI) client — this represents an
authorized operator workstation issuing normal, authenticated control
commands to the water-control process via the WaterGuard Gateway. Every
function in this module produces a fully valid, correctly-authenticated WCP
message, and is used both:

    (a) as the "normal operation" demonstration on its own
        (`python3 -m client.legit_hmi_client --register 0 --value 180`), and

    (b) as a building block inside attacker/device_a_attacker.py for the
        replay_attack scenario, which needs to start from one genuinely
        valid, captured message before replaying it.
"""

from __future__ import annotations

import argparse
import secrets
import socket
import time
from typing import Optional

from shared import config, crypto_utils
from shared.wcp_protocol import build_canonical_payload, canonical_bytes, recv_wcp_line, send_wcp_line


def build_signed_message(client_id: str, register: int, value: int, timestamp: Optional[float] = None,
                          nonce: Optional[str] = None) -> dict:
    """
    Builds one fully valid, correctly-signed WCP message. `timestamp` and
    `nonce` are normally left to their defaults (current time, fresh random
    nonce); the parameters exist so device_a_attacker.py's replay_attack
    scenario can call this once to mint a single "captured" message and then
    resend that EXACT dict multiple times unmodified.
    """
    ts = timestamp if timestamp is not None else time.time()
    nc = nonce if nonce is not None else secrets.token_hex(16)
    payload = build_canonical_payload(client_id, register, value, ts, nc)
    tag = crypto_utils.hmac_sha256_hex(config.COMMAND_HMAC_KEY, canonical_bytes(payload))
    return {**payload, "hmac": tag}


def send_message(msg: dict, *, gateway_host: str = "127.0.0.1", gateway_port: Optional[int] = None,
                  bind_ip: Optional[str] = None, timeout: float = 5.0) -> dict:
    """
    Opens a fresh TCP connection to the Gateway, sends one WCP message, reads
    and returns the parsed JSON response. `bind_ip` lets a caller (used by
    the attacker suite's source_spoofing scenario) force the outgoing
    connection's local source address, e.g. to a loopback alias like
    127.0.0.2, to simulate originating from a different host without needing
    a second physical/virtual machine.
    """
    port = gateway_port if gateway_port is not None else config.GATEWAY_WCP_PORT
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if bind_ip:
            sock.bind((bind_ip, 0))
        sock.settimeout(timeout)
        sock.connect((gateway_host, port))
        send_wcp_line(sock, msg)
        raw_response = recv_wcp_line(sock, max_bytes=4096, timeout=timeout)
        if not raw_response:
            return {"decision": "NO_RESPONSE", "reason": "gateway closed the connection without responding"}
        import json
        return json.loads(raw_response.decode("utf-8"))
    finally:
        sock.close()


def send_command(client_id: str, register: int, value: int, *, gateway_host: str = "127.0.0.1",
                  gateway_port: Optional[int] = None, bind_ip: Optional[str] = None) -> dict:
    """Convenience wrapper: build a fresh signed message for (register, value) and send it immediately."""
    msg = build_signed_message(client_id, register, value)
    return send_message(msg, gateway_host=gateway_host, gateway_port=gateway_port, bind_ip=bind_ip)


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard legitimate HMI client")
    parser.add_argument("--client-id", default="hmi-01")
    parser.add_argument("--gateway-host", default="127.0.0.1")
    parser.add_argument("--gateway-port", type=int, default=config.GATEWAY_WCP_PORT)
    parser.add_argument("--register", type=int, required=True, help="0=chlorine (x100 ppm), 1=valve (%%)")
    parser.add_argument("--value", type=int, required=True)
    args = parser.parse_args()

    response = send_command(
        args.client_id, args.register, args.value,
        gateway_host=args.gateway_host, gateway_port=args.gateway_port,
    )
    print(f"[legit_hmi_client] sent register={args.register} value={args.value} -> {response}")


if __name__ == "__main__":
    main()
