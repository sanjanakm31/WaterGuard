from __future__ import annotations

import json
import socket
import struct
import time
from pathlib import Path

import pytest

from client.legit_hmi_client import build_signed_message, send_command
from controller.modbus_forwarder import LoopbackTestForwarder
from gateway import evidence_store
from gateway.waterguard_gateway import WaterGuardGateway
from shared import config, crypto_utils
from shared.wcp_protocol import MalformedMessageError, parse_wire_line
from tools.export_evidence_pcap import export_file, verify_export


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(evidence_store, "DB_PATH", tmp_path / "evidence.db")
    evidence_store.init_db()
    return evidence_store.DB_PATH


def test_crypto_round_trip_and_tamper_detection():
    plaintext = b"waterguard-evidence"
    nonce, ciphertext = crypto_utils.aes_gcm_encrypt(config.EVIDENCE_AES_KEY, plaintext)
    assert crypto_utils.aes_gcm_decrypt(config.EVIDENCE_AES_KEY, nonce, ciphertext) == plaintext
    corrupt = bytearray(ciphertext)
    corrupt[0] ^= 1
    with pytest.raises(Exception):
        crypto_utils.aes_gcm_decrypt(config.EVIDENCE_AES_KEY, nonce, bytes(corrupt))


@pytest.mark.parametrize("message", [
    {"client_id": "hmi-01"},
    {"client_id": "hmi-01", "register": 0, "value": 20, "timestamp": float("nan"), "nonce": "ab" * 16, "hmac": "00" * 32},
    {"client_id": "hmi-01", "register": 0, "value": 20, "timestamp": time.time(), "nonce": "ab" * 16, "hmac": "00" * 32, "extra": True},
])
def test_protocol_rejects_malformed_or_ambiguous_messages(message):
    with pytest.raises(MalformedMessageError):
        parse_wire_line(json.dumps(message).encode(), config.MAX_WCP_MESSAGE_BYTES)


def test_gateway_allows_safe_commands_and_blocks_attacks(isolated_db):
    port, modbus_port = free_port(), free_port()
    while modbus_port == port:
        modbus_port = free_port()
    forwarder = LoopbackTestForwarder()
    gateway = WaterGuardGateway(
        forwarder,
        host="127.0.0.1",
        port=port,
        modbus_intake_port=modbus_port,
    )
    gateway.start(blocking=False)
    try:
        allowed = send_command("hmi-01", 1, 55, gateway_host="127.0.0.1", gateway_port=port)
        unsafe = build_signed_message("hmi-01", 0, 2500)
        from client.legit_hmi_client import send_message
        blocked = send_message(unsafe, gateway_host="127.0.0.1", gateway_port=port)
        replayed = send_message(build_signed_message("hmi-01", 1, 60, nonce=unsafe["nonce"]), gateway_host="127.0.0.1", gateway_port=port)
        forged = build_signed_message("hmi-01", 1, 70)
        forged["hmac"] = "00" * 32
        assert send_message(forged, gateway_host="127.0.0.1", gateway_port=port)["reason"] == "invalid_hmac"
        recovered = build_signed_message("hmi-01", 1, 70, timestamp=forged["timestamp"], nonce=forged["nonce"])
        assert send_message(recovered, gateway_host="127.0.0.1", gateway_port=port)["decision"] == "ALLOW"
        raw_write = struct.pack(">HHHBBHH", 1, 0, 6, 1, 6, 0, 2500)
        with socket.create_connection(("127.0.0.1", modbus_port), timeout=2) as sock:
            sock.sendall(raw_write)
            modbus_exception = sock.recv(9)
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(b"x" * (config.MAX_WCP_MESSAGE_BYTES * 2) + b"\n")
            sock.shutdown(socket.SHUT_WR)
            oversized_response = json.loads(sock.makefile("rb").readline())
        assert len(modbus_exception) == 9
        assert modbus_exception[7:] == b"\x86\x01"
        assert oversized_response["decision"] == "BLOCK"
        assert oversized_response["reason"] == "malformed_request"
        assert allowed["decision"] == "ALLOW"
        assert blocked["reason"] == "unsafe_setpoint"
        # The unsafe command was authenticated, so its nonce is consumed.
        assert replayed["reason"] == "replay_attack"
        assert forwarder.written == [(1, 55), (1, 70)]
        recent_reasons = {event["reason"] for event in evidence_store.fetch_recent_events(20)}
        assert "unauthenticated_modbus" in recent_reasons
        assert "malformed_request" in recent_reasons
    finally:
        gateway.stop()


def test_process_simulation_tick_uses_supported_modbus_client_api():
    from controller.device_b_controller import _process_simulation_tick

    class Result:
        def __init__(self, registers=None):
            self.registers = registers or []

        @staticmethod
        def isError():
            return False

    class Client:
        def __init__(self):
            self.registers = {0: 150, 1: 50, 2: 120}

        def read_holding_registers(self, address, *, count, device_id):
            assert count == 1 and device_id == 1
            return Result([self.registers[address]])

        def write_register(self, address, value, *, device_id):
            assert device_id == 1
            self.registers[address] = value
            return Result()

    class FixedRandom:
        @staticmethod
        def randint(_low, _high):
            return 2

        @staticmethod
        def random():
            return 0.1

    client = Client()
    _process_simulation_tick(client, FixedRandom)
    assert client.registers[2] == 122
    assert client.registers[0] == 149


def test_evidence_verifies_duplicate_cleartext_columns(isolated_db):
    evidence_store.record_event(client_id="hmi-01", peer_ip="127.0.0.1", register=1, value=50,
                                stage="decision", decision="ALLOW", reason="all_checks_passed")
    row = evidence_store.fetch_all_raw_rows()[0]
    assert evidence_store.decrypt_and_verify_event(row)[0]
    row["reason"] = "forged-display-value"
    intact, _, detail = evidence_store.decrypt_and_verify_event(row)
    assert not intact and "cleartext column mismatch" in detail


def test_encrypted_file_export_round_trip(isolated_db, tmp_path: Path):
    source = tmp_path / "attack.pcap"
    source.write_bytes(b"pcap-test-payload")
    encrypted, manifest = export_file(source)
    assert source.read_bytes() == b"pcap-test-payload"
    assert verify_export(encrypted, manifest)[0]
    blob = bytearray(encrypted.read_bytes())
    blob[-1] ^= 1
    encrypted.write_bytes(blob)
    assert not verify_export(encrypted, manifest)[0]

    encrypted, manifest = export_file(source)
    metadata = json.loads(manifest.read_text(encoding="utf-8"))
    metadata["original_filename"] = "forged-name.pcap"
    manifest.write_text(json.dumps(metadata), encoding="utf-8")
    ok, detail = verify_export(encrypted, manifest)
    assert not ok
    assert "metadata tampered" in detail


def test_unexpected_gateway_error_is_recorded(isolated_db, monkeypatch):
    port, modbus_port = free_port(), free_port()
    while modbus_port == port:
        modbus_port = free_port()
    forwarder = LoopbackTestForwarder()
    gateway = WaterGuardGateway(
        forwarder,
        host="127.0.0.1",
        port=port,
        modbus_intake_port=modbus_port,
    )

    def explode(*_args, **_kwargs):
        raise RuntimeError("forced regression-test failure")

    monkeypatch.setattr(gateway, "_process_message", explode)
    gateway.start(blocking=False)
    try:
        from client.legit_hmi_client import send_message

        response = send_message(
            build_signed_message("hmi-01", 1, 55),
            gateway_host="127.0.0.1",
            gateway_port=port,
        )
        # An internal failure is ERROR, distinct from a confirmed policy BLOCK.
        assert response["decision"] == "ERROR"
        assert response["reason"] == "internal_error"
        assert response["stage"] == "internal"
        event = evidence_store.fetch_recent_events(limit=1)[0]
        assert event["event_id"] == response["event_id"]
        assert event["decision"] == "ERROR"
        assert event["reason"] == "internal_error"
        assert event["stage"] == "internal"
        assert event["integrity_status"] == "INTACT"
        assert forwarder.written == []
    finally:
        gateway.stop()
