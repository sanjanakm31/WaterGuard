"""
run_local_pipeline_demo.py

Runs the ENTIRE WaterGuard validation pipeline end-to-end, in-process, using
LoopbackTestForwarder in place of a real Device B (so this script has zero
dependency on pymodbus and can run anywhere Python + `cryptography` are
installed -- including a sandbox with no network access).

This is a verification/proof harness, not the graded demo: for your actual
submission, run Device B (controller/device_b_controller.py), the Gateway
WITHOUT --test-mode, and Device A's scenarios as three genuinely separate
processes (ideally on three separate VMs) per README.md.

What this script proves, with real, inspectable output:
    1. The legitimate HMI client's two commands are ALLOWED and reach the
       (simulated) controller.
    2. Every one of the 9 attack scenarios is BLOCKED, each for the
       specific reason the corresponding pipeline stage is designed to
       catch.
    3. Every ALLOW and BLOCK decision is durably recorded in the encrypted
       SQLite evidence store.
    4. The tamper-evidence verification tool reports every record INTACT
       before tampering, then correctly isolates and flags the ONE record
       an attacker corrupts, while every other record still verifies
       INTACT -- without ever needing to trust the tampered ciphertext.
"""

from __future__ import annotations

import json
import secrets as _secrets
import socket
import struct
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
ENV_PATH = REPO_ROOT / ".env"


def _ensure_env() -> None:
    """Generates a throwaway .env for this demo run if one does not already exist."""
    if ENV_PATH.exists():
        return
    lines = [
        f"WG_COMMAND_HMAC_KEY={_secrets.token_hex(32)}",
        f"WG_EVIDENCE_HMAC_KEY={_secrets.token_hex(32)}",
        f"WG_EVIDENCE_AES_KEY={_secrets.token_hex(32)}",
        "WG_AUTHORIZED_SOURCES=hmi-01=127.0.0.1",
        "WG_GATEWAY_WCP_PORT=6000",
        "WG_GATEWAY_MODBUS_PORT=1502",
    ]
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[demo] generated a fresh {ENV_PATH.name} for this run (not for production use)\n")


_ensure_env()
sys.path.insert(0, str(REPO_ROOT))

from attacker import device_a_attacker as atk  # noqa: E402
from client.legit_hmi_client import send_command  # noqa: E402
from controller.modbus_forwarder import LoopbackTestForwarder  # noqa: E402
from gateway import evidence_store  # noqa: E402
from gateway.waterguard_gateway import WaterGuardGateway  # noqa: E402
from shared import config  # noqa: E402
from tools import verify_evidence_integrity  # noqa: E402


def _hr(title: str) -> None:
    print("\n" + "=" * 100)
    print(title)
    print("=" * 100)


def main() -> None:
    _hr("WATERGUARD -- LOCAL PIPELINE DEMO (LoopbackTestForwarder stands in for Device B)")

    # Fresh evidence DB for a clean, readable demo run.
    if evidence_store.DB_PATH.exists():
        evidence_store.DB_PATH.unlink()

    forwarder = LoopbackTestForwarder()
    gateway = WaterGuardGateway(forwarder, port=config.GATEWAY_WCP_PORT)
    gateway.start(blocking=False)
    time.sleep(0.3)

    host, port = "127.0.0.1", config.GATEWAY_WCP_PORT

    _hr("NORMAL OPERATION (legitimate HMI client, hmi-01)")
    r1 = send_command("hmi-01", config.REGISTER_VALVE_POSITION_PCT, 55, gateway_host=host, gateway_port=port)
    print(f"legit valve write   register=1 value=55  -> {r1}")
    r2 = send_command("hmi-01", config.REGISTER_CHLORINE_PPM_X100, 180, gateway_host=host, gateway_port=port)
    print(f"legit chlorine dose register=0 value=180 -> {r2}")
    assert r1["decision"] == "ALLOW" and r2["decision"] == "ALLOW", "legitimate commands must be ALLOWed"

    scenarios = [
        ("1. unauthorized-source", lambda: atk.attack_unauthorized_source(host, port), "unauthorized_source"),
        ("2. source-spoofing", lambda: atk.attack_source_spoofing(host, port), "source_spoofing"),
        ("3. command-forgery", lambda: atk.attack_command_forgery(host, port), "invalid_hmac"),
        ("4. forged-hmac", lambda: atk.attack_forged_hmac(host, port), "invalid_hmac"),
        ("5. unsafe-setpoint", lambda: atk.attack_unsafe_setpoint(host, port), "unsafe_setpoint"),
        ("6. restricted-register", lambda: atk.attack_restricted_register(host, port), "restricted_register"),
        ("7. replay", lambda: atk.attack_replay(host, port), None),
        ("8. malformed-request", lambda: atk.attack_malformed_request(host, port), None),
    ]

    _hr("ATTACK SUITE (Device A) -- expected outcome noted for each")
    all_passed = True
    results_by_name: dict[str, object] = {}
    for name, fn, expected_reason in scenarios:
        result = fn()
        results_by_name[name] = result
        print(f"\n--- {name} ---")
        print(json.dumps(result, indent=2, default=str))
        if expected_reason is not None:
            ok = result.get("decision") == "BLOCK" and result.get("reason") == expected_reason
            print(f"    => {'PASS' if ok else 'FAIL'}: expected BLOCK/{expected_reason}, got "
                  f"{result.get('decision')}/{result.get('reason')}")
            all_passed = all_passed and ok

    # replay: step_1 must ALLOW, steps 2 & 3 must BLOCK/replay_attack
    # (reuse the result captured above -- do NOT call the scenario again, since
    # every call mints a fresh nonce/timestamp and would send a second real
    # write through the pipeline, double-counting "writes that reached the
    # controller" below)
    replay_result = results_by_name["7. replay"]
    r_ok = (
        replay_result["step_1_original_send"]["decision"] == "ALLOW"
        and replay_result["step_2_immediate_replay"]["decision"] == "BLOCK"
        and replay_result["step_2_immediate_replay"]["reason"] == "replay_attack"
        and replay_result["step_3_aged_replay"]["decision"] == "BLOCK"
        and replay_result["step_3_aged_replay"]["reason"] == "replay_attack"
    )
    print(f"\n    => replay scenario structural check: {'PASS' if r_ok else 'FAIL'}")
    all_passed = all_passed and r_ok

    # malformed-request: every variant must be BLOCK/malformed_request (never NO_RESPONSE, never a crash)
    malformed_result = results_by_name["8. malformed-request"]
    m_ok = all(v.get("decision") == "BLOCK" and v.get("reason") == "malformed_request" for v in malformed_result.values())
    print(f"    => malformed-request structural check (all variants BLOCK/malformed_request): "
          f"{'PASS' if m_ok else 'FAIL'}")
    all_passed = all_passed and m_ok

    # A native Modbus/TCP request has no WaterGuard HMAC envelope. The gateway
    # records it, responds with Modbus exception 0x01, and never forwards it.
    transaction_id = 77
    raw_write = struct.pack(">HHHBBHH", transaction_id, 0, 6, 1, 6, 0, 2500)
    with socket.create_connection((host, config.GATEWAY_MODBUS_PORT), timeout=2.0) as sock:
        sock.sendall(raw_write)
        raw_response = sock.recv(256)
    raw_ok = (
        len(raw_response) == 9
        and struct.unpack(">H", raw_response[:2])[0] == transaction_id
        and raw_response[-2:] == b"\x86\x01"
    )
    print("\n--- 9. unauthenticated native Modbus/TCP ---")
    print(f"response_hex={raw_response.hex()}")
    print(f"    => {'PASS' if raw_ok else 'FAIL'}: expected Modbus exception 86/01")
    all_passed = all_passed and raw_ok

    _hr("WRITES THAT ACTUALLY REACHED THE (SIMULATED) CONTROLLER")
    print(f"forwarder.written = {forwarder.written}")
    print(f"count = {len(forwarder.written)} (expected 3: 2 legitimate commands + 1 replay scenario's "
          f"'original' send; every BLOCKed WCP and native-Modbus attack produced ZERO writes)")
    assert len(forwarder.written) == 3, f"expected exactly 3 writes to reach the controller, got {len(forwarder.written)}"

    _hr("EVIDENCE STORE -- every ALLOW/BLOCK decision cryptographically verified")
    events = evidence_store.fetch_recent_events(limit=100)
    for ev in reversed(events):  # chronological order
        print(f"  [{ev['decision']:<5}] stage={ev['stage']:<20} reason={ev['reason']:<20} "
              f"client={ev['client_id']!s:<25} peer={ev['peer_ip']}")
    print(f"\nTotal events recorded: {len(events)}")

    _hr("TAMPER-EVIDENCE VERIFICATION -- BEFORE tampering (every row must be INTACT)")
    rc_before = verify_evidence_integrity.main()

    _hr("SIMULATING AN EVIDENCE-TAMPERING ATTACK")
    tamper_result = atk.attack_evidence_tampering()
    print(json.dumps(tamper_result, indent=2, default=str))

    _hr("TAMPER-EVIDENCE VERIFICATION -- AFTER tampering (exactly ONE row must now be TAMPERED)")
    rc_after = verify_evidence_integrity.main()

    _hr("DEMO SUMMARY")
    print(f"All 9 attack scenarios blocked for their expected reason: {'PASS' if all_passed else 'FAIL'}")
    print(f"Integrity check before tampering exited: {rc_before} (0 = all intact, expected 0)")
    print(f"Integrity check after tampering exited:  {rc_after} (1 = tamper detected, expected 1)")
    overall_ok = all_passed and rc_before == 0 and rc_after == 1
    print(f"\nOVERALL: {'ALL CHECKS PASSED' if overall_ok else 'ONE OR MORE CHECKS FAILED -- see above'}")

    gateway.stop()
    sys.exit(0 if overall_ok else 1)


if __name__ == "__main__":
    main()
