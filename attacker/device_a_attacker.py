"""
attacker/device_a_attacker.py

Device A — the controlled attacker simulator. This tool NEVER talks to
anything outside the project's own simulated environment: every scenario
targets either the WaterGuard Gateway's WCP/native-Modbus ports or Device B's Modbus port,
both of which are components you started yourself on your own machine(s)
per the deployment guide. Nothing here is generic exploit tooling — each
scenario is a narrow, purpose-built script that exercises exactly one
validation stage of the Gateway (or, for malformed_modbus_direct, of
Device B directly) so that the resulting BLOCK reason maps cleanly onto one
line of the design document and one row of the testing chapter.

SCENARIOS
---------
  unauthorized-source        client_id not present in the authorized-source
                              registry at all.
  source-spoofing            client_id IS a registered identity (hmi-01),
                              but the connection is made from a different
                              source address than the one on file for it
                              (simulated locally via a loopback alias,
                              127.0.0.2 -- see --bind-ip).
  command-forgery            well-formed message, but the 'hmac' field is
                              missing/garbage -- no attempt at a real tag.
  forged-hmac                well-formed message, 'hmac' computed with a
                              fabricated (wrong) key -- a plausible-looking
                              but invalid forged tag. Note: the Gateway
                              rejects this identically to command-forgery
                              (reason=invalid_hmac) -- this is intentional
                              and is a security property, not a bug.
  unsafe-setpoint             valid source, valid REAL HMAC (modeling an
                              authenticated-but-malicious or compromised
                              credential), value outside the configured
                              safe bound.
  restricted-register         valid source, valid real HMAC, but targets the
                              read-only flow-sensor register.
  unauthenticated-modbus      uses PyModbus to issue a real native Modbus
                              write to the Gateway's untrusted port. Because
                              Modbus cannot carry the required HMAC, the
                              Gateway records and blocks it without forwarding.
  replay                     captures one genuinely valid, freshly-issued
                              command and resends the identical bytes twice
                              more: once immediately (caught by nonce reuse)
                              and once with an artificially aged timestamp
                              (caught by the freshness window).
  malformed-request           a battery of structurally invalid WCP messages
                              (bad JSON, missing fields, out-of-range values,
                              oversized payload, non-UTF-8 bytes) sent
                              directly on the wire, bypassing the normal
                              message builder entirely.
  malformed-modbus-direct     bypasses the Gateway entirely and sends raw,
                              non-Modbus-conformant bytes straight at
                              Device B's Modbus TCP port, to test Device B's
                              own frame-level robustness and to demonstrate
                              why the Gateway-only access path must be
                              enforced by network segmentation as well.
  evidence-tampering           directly edits one row of the local evidence
                              SQLite database (simulating an attacker who
                              has obtained filesystem access to the
                              Gateway's evidence store) so that
                              tools/verify_evidence_integrity.py can be run
                              afterward to demonstrate that the tamper is
                              detected.
  run-all                     runs every Gateway scenario above (all
                              except malformed-modbus-direct and
                              evidence-tampering, which need Device B /
                              the evidence DB respectively) in sequence and
                              prints a results table.
"""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import sqlite3
import time
from pathlib import Path
from typing import Optional

from client.legit_hmi_client import build_signed_message, send_message
from shared import config, crypto_utils
from shared.wcp_protocol import canonical_bytes

WRONG_KEY = bytes.fromhex("00" * 32)  # a key the attacker fabricated -- guaranteed != the real PSK


def _send_raw(raw_bytes: bytes, host: str, port: int, bind_ip: Optional[str] = None, timeout: float = 5.0) -> dict:
    """Sends arbitrary raw bytes (NOT necessarily valid JSON/WCP) directly to the Gateway's WCP port."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if bind_ip:
            sock.bind((bind_ip, 0))
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.sendall(raw_bytes if raw_bytes.endswith(b"\n") else raw_bytes + b"\n")
        buf = b""
        while b"\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        line, _, _ = buf.partition(b"\n")
        if not line:
            return {"decision": "NO_RESPONSE", "reason": "gateway closed the connection without responding"}
        return json.loads(line.decode("utf-8", errors="replace"))
    finally:
        sock.close()


# --------------------------------------------------------------------------- #
# Scenario implementations
# --------------------------------------------------------------------------- #

def attack_unauthorized_source(host: str, port: int) -> dict:
    msg = build_signed_message(client_id="rogue-engineering-laptop", register=config.REGISTER_VALVE_POSITION_PCT, value=50)
    return send_message(msg, gateway_host=host, gateway_port=port)


def attack_source_spoofing(host: str, port: int, spoof_bind_ip: str = "127.0.0.2") -> dict:
    # Claims to BE the registered client "hmi-01", but connects from a
    # different local address than the one on file for hmi-01 (127.0.0.1).
    msg = build_signed_message(client_id="hmi-01", register=config.REGISTER_VALVE_POSITION_PCT, value=50)
    return send_message(msg, gateway_host=host, gateway_port=port, bind_ip=spoof_bind_ip)


def attack_command_forgery(host: str, port: int) -> dict:
    payload = {
        "client_id": "hmi-01",
        "register": config.REGISTER_CHLORINE_PPM_X100,
        "value": 250,
        "timestamp": time.time(),
        "nonce": secrets.token_hex(16),
    }
    msg = {**payload, "hmac": "0" * 64}  # syntactically valid hex, cryptographically meaningless
    return send_message(msg, gateway_host=host, gateway_port=port)


def attack_forged_hmac(host: str, port: int) -> dict:
    payload = {
        "client_id": "hmi-01",
        "register": config.REGISTER_CHLORINE_PPM_X100,
        "value": 250,
        "timestamp": time.time(),
        "nonce": secrets.token_hex(16),
    }
    forged_tag = crypto_utils.hmac_sha256_hex(WRONG_KEY, canonical_bytes(payload))
    msg = {**payload, "hmac": forged_tag}
    return send_message(msg, gateway_host=host, gateway_port=port)


def attack_unsafe_setpoint(host: str, port: int) -> dict:
    # Valid source + valid REAL hmac -- models an authenticated-but-malicious
    # or compromised-credential client attempting to push chlorine dosing to
    # a dangerous level (2500 -> 25.00 ppm, far above the 4.00 ppm bound).
    msg = build_signed_message(client_id="hmi-01", register=config.REGISTER_CHLORINE_PPM_X100, value=2500)
    return send_message(msg, gateway_host=host, gateway_port=port)


def attack_restricted_register(host: str, port: int) -> dict:
    msg = build_signed_message(client_id="hmi-01", register=config.REGISTER_FLOW_RATE_LPM, value=999)
    return send_message(msg, gateway_host=host, gateway_port=port)


def attack_unauthenticated_modbus(host: str, port: int) -> dict:
    """Issue a real PyModbus write to the gateway's untrusted Modbus port."""
    from pymodbus.client import ModbusTcpClient

    client = ModbusTcpClient(host, port=port, timeout=3)
    try:
        if not client.connect():
            return {
                "decision": "ERROR",
                "reason": f"could not connect to gateway Modbus port {host}:{port}",
            }
        response = client.write_register(
            config.REGISTER_CHLORINE_PPM_X100,
            2500,
            device_id=1,
        )
        # A timeout/transport error is not evidence of a security rejection.
        blocked = (getattr(response, "function_code", None) == 134
                   and getattr(response, "exception_code", None) == 1)
        if response.isError() and not blocked:
            return {"decision": "ERROR", "reason": "transport_or_unexpected_modbus_error",
                    "modbus_response": str(response)}
        return {
            "decision": "BLOCK" if blocked else "UNEXPECTED_ALLOW",
            "reason": "unauthenticated_modbus" if blocked else "gateway accepted raw Modbus unexpectedly",
            "modbus_response": str(response),
        }
    finally:
        client.close()


def attack_replay(host: str, port: int) -> dict:
    results = {}

    # Step 1: a genuinely valid, freshly-issued command -- expect ALLOW.
    captured = build_signed_message(client_id="hmi-01", register=config.REGISTER_VALVE_POSITION_PCT, value=60)
    results["step_1_original_send"] = send_message(dict(captured), gateway_host=host, gateway_port=port)

    # Step 2: immediately resend the EXACT same bytes -- expect BLOCK via nonce reuse.
    results["step_2_immediate_replay"] = send_message(dict(captured), gateway_host=host, gateway_port=port)

    # Step 3: resend again with the timestamp artificially aged past the
    # freshness window (nonce also reused) -- expect BLOCK, and would still
    # be BLOCK via the freshness check alone even with a brand-new nonce.
    aged = dict(captured)
    aged["timestamp"] = captured["timestamp"] - (config.REPLAY_WINDOW_SECONDS + 30.0)
    results["step_3_aged_replay"] = send_message(aged, gateway_host=host, gateway_port=port)

    return results


def attack_malformed_request(host: str, port: int) -> dict:
    variants = {
        "invalid_json": b"{not valid json at all",
        "missing_fields": json.dumps({"client_id": "hmi-01"}).encode("utf-8"),
        "wrong_types": json.dumps({
            "client_id": "hmi-01", "register": "zero", "value": "two-fifty",
            "timestamp": "not-a-number", "nonce": 12345, "hmac": "0" * 64,
        }).encode("utf-8"),
        "register_out_of_range": json.dumps({
            "client_id": "hmi-01", "register": 999999, "value": 50,
            "timestamp": time.time(), "nonce": secrets.token_hex(16), "hmac": "0" * 64,
        }).encode("utf-8"),
        "oversized_payload": (json.dumps({
            "client_id": "hmi-01", "register": 0, "value": 0, "timestamp": time.time(),
            "nonce": secrets.token_hex(16), "hmac": "0" * 64, "padding": "A" * 8000,
        })).encode("utf-8"),
        "non_utf8_bytes": b"\xff\xfe\x00\x01garbage-binary-not-utf8\x00\x00",
    }
    results = {}
    for name, raw in variants.items():
        try:
            results[name] = _send_raw(raw, host, port)
        except Exception as exc:  # a variant that crashes the CLIENT is fine to report; the GATEWAY must not crash
            results[name] = {"client_side_exception": repr(exc)}
    return results


def attack_malformed_modbus_direct(controller_host: str, controller_port: int) -> dict:
    """
    Bypasses the Gateway entirely: connects straight to Device B's raw
    Modbus TCP port and sends bytes that do not form a valid Modbus MBAP
    header + PDU, to verify Device B does not crash or misbehave when
    reached directly. This also demonstrates why network segmentation
    (Device B accepting connections ONLY from the Gateway's VM) is a
    necessary complement to the Gateway's application-layer checks, not a
    redundant precaution.
    """
    garbage_frames = [
        b"\x00\x00\x00\x00\x00\x99\x01\x10\xff\xff\xff\xff",  # bogus over-long MBAP length field
        b"NOT_MODBUS_AT_ALL" * 4,
        b"\x00" * 2,  # truncated / empty frame
    ]
    results = {}
    for i, frame in enumerate(garbage_frames, start=1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(3.0)
            sock.connect((controller_host, controller_port))
            sock.sendall(frame)
            try:
                reply = sock.recv(256)
                results[f"frame_{i}"] = f"connection accepted bytes; reply={reply!r}"
            except socket.timeout:
                results[f"frame_{i}"] = "connection accepted bytes; no reply (server ignored malformed frame, as expected)"
        except (ConnectionRefusedError, OSError) as exc:
            results[f"frame_{i}"] = f"connection rejected/failed: {exc!r}"
        finally:
            sock.close()
    return results


def attack_evidence_tampering(db_path: Optional[Path] = None) -> dict:
    """
    Simulates an attacker with filesystem access to the Gateway's evidence
    database directly corrupting the most recent stored event's ciphertext,
    WITHOUT knowledge of EVIDENCE_HMAC_KEY or EVIDENCE_AES_KEY (a real
    attacker who had those keys would not need to tamper with ciphertext at
    all). Run tools/verify_evidence_integrity.py afterward to confirm the
    tamper is detected.
    """
    path = db_path or (Path(__file__).resolve().parent.parent / "data" / "waterguard_evidence.db")
    if not path.exists():
        return {"error": f"no evidence database found at {path}; run the Gateway and send at least one command first"}

    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT id, event_id, encrypted_payload FROM security_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return {"error": "evidence database has no rows to tamper with"}
        row_id, event_id, encrypted_payload = row
        tampered = bytearray(encrypted_payload)
        tampered[0] ^= 0xFF  # flip every bit of the first byte of the ciphertext
        conn.execute(
            "UPDATE security_events SET encrypted_payload = ? WHERE id = ?", (bytes(tampered), row_id)
        )
        conn.commit()
        return {
            "tampered_event_id": event_id,
            "row_id": row_id,
            "action": "flipped the first byte of encrypted_payload",
            "next_step": "run: python3 -m tools.verify_evidence_integrity",
        }
    finally:
        conn.close()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def _print_result(title: str, result) -> None:
    print(f"\n=== {title} ===")
    print(json.dumps(result, indent=2, default=str))


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard Device A — controlled attacker suite")
    parser.add_argument("--gateway-host", default="127.0.0.1")
    parser.add_argument("--gateway-port", type=int, default=config.GATEWAY_WCP_PORT)
    parser.add_argument("--controller-host", default=config.CONTROLLER_HOST)
    parser.add_argument("--controller-port", type=int, default=config.CONTROLLER_MODBUS_PORT)
    parser.add_argument(
        "scenario",
        choices=[
            "unauthorized-source", "source-spoofing", "command-forgery", "forged-hmac",
            "unsafe-setpoint", "restricted-register", "replay", "malformed-request",
            "unauthenticated-modbus", "malformed-modbus-direct", "evidence-tampering", "run-all",
        ],
    )
    args = parser.parse_args()

    gh, gp = args.gateway_host, args.gateway_port

    if args.scenario == "unauthorized-source":
        _print_result("unauthorized-source", attack_unauthorized_source(gh, gp))
    elif args.scenario == "source-spoofing":
        _print_result("source-spoofing", attack_source_spoofing(gh, gp))
    elif args.scenario == "command-forgery":
        _print_result("command-forgery", attack_command_forgery(gh, gp))
    elif args.scenario == "forged-hmac":
        _print_result("forged-hmac", attack_forged_hmac(gh, gp))
    elif args.scenario == "unsafe-setpoint":
        _print_result("unsafe-setpoint", attack_unsafe_setpoint(gh, gp))
    elif args.scenario == "restricted-register":
        _print_result("restricted-register", attack_restricted_register(gh, gp))
    elif args.scenario == "unauthenticated-modbus":
        _print_result(
            "unauthenticated-modbus",
            attack_unauthenticated_modbus(gh, config.GATEWAY_MODBUS_PORT),
        )
    elif args.scenario == "replay":
        _print_result("replay", attack_replay(gh, gp))
    elif args.scenario == "malformed-request":
        _print_result("malformed-request", attack_malformed_request(gh, gp))
    elif args.scenario == "malformed-modbus-direct":
        _print_result("malformed-modbus-direct", attack_malformed_modbus_direct(args.controller_host, args.controller_port))
    elif args.scenario == "evidence-tampering":
        _print_result("evidence-tampering", attack_evidence_tampering())
    elif args.scenario == "run-all":
        _print_result("unauthorized-source", attack_unauthorized_source(gh, gp))
        _print_result("source-spoofing", attack_source_spoofing(gh, gp))
        _print_result("command-forgery", attack_command_forgery(gh, gp))
        _print_result("forged-hmac", attack_forged_hmac(gh, gp))
        _print_result("unsafe-setpoint", attack_unsafe_setpoint(gh, gp))
        _print_result("restricted-register", attack_restricted_register(gh, gp))
        _print_result(
            "unauthenticated-modbus",
            attack_unauthenticated_modbus(gh, config.GATEWAY_MODBUS_PORT),
        )
        _print_result("replay", attack_replay(gh, gp))
        _print_result("malformed-request", attack_malformed_request(gh, gp))


if __name__ == "__main__":
    main()
