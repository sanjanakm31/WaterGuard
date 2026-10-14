"""Read genuine SQLite bytes and verify them; tamper only a disposable copy."""
import json
import sqlite3
import uuid
from pathlib import Path
from gateway import evidence_store as store
from shared import config, crypto_utils

def raw_row(event_id: str) -> dict:
    with store._lock, store._connection() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM security_events WHERE event_id=?", (event_id,)).fetchone()
    if row is None:
        raise KeyError(event_id)
    return dict(row)

def show_proof(event_id: str) -> dict:
    row = raw_row(event_id)
    intact, record, detail = store.decrypt_and_verify_event(row)
    output = {
        "event_id": event_id, "database": str(store.DB_PATH), "table": "security_events",
        "status": "INTACT" if intact else "TAMPERED", "detail": detail,
        "payload_hash": row["payload_hash"], "hash_hmac": row["hash_hmac"],
        "aes_nonce_hex": bytes(row["aes_nonce"]).hex(),
        "ciphertext_hex": bytes(row["encrypted_payload"]).hex(),
        "gcm_tag_hex": bytes(row["encrypted_payload"])[-16:].hex(),
        "ciphertext_bytes": len(row["encrypted_payload"]),
        "metadata": {k: row[k] for k in ("id", "event_id", "ts", "client_id", "peer_ip", "stage", "decision", "reason")},
        "algorithm": "AES-256-GCM: 32-byte key, random 12-byte nonce, 16-byte authentication tag",
        "source_files": ["gateway/evidence_store.py", "shared/crypto_utils.py", "gateway/evidence_proof.py"],
        "checks": {"aes_gcm": False, "sha256": False, "evidence_hmac": False, "metadata": False},
    }
    try:
        plain = crypto_utils.aes_gcm_decrypt(config.EVIDENCE_AES_KEY, bytes(row["aes_nonce"]), bytes(row["encrypted_payload"]))
        output["checks"]["aes_gcm"] = True
        recomputed = crypto_utils.sha256_hex(plain)
        output["recomputed_hash"] = recomputed
        output["checks"]["sha256"] = recomputed == row["payload_hash"]
        output["checks"]["evidence_hmac"] = crypto_utils.hmac_verify(config.EVIDENCE_HMAC_KEY, row["payload_hash"].encode(), row["hash_hmac"])
        output["checks"]["metadata"] = intact
        # Reveal plaintext only after ALL checks pass, including clear columns.
        if intact:
            output.update(plaintext=plain.decode(), plaintext_hex=plain.hex(), record=record)
            command = record.get("extra", {}).get("command")
            if command:
                from shared.wcp_protocol import canonical_bytes
                signed = canonical_bytes(command)
                output["command_proof"] = {"json": command, "signed_bytes_hex": signed.hex(),
                    "hmac_valid": crypto_utils.hmac_verify(config.COMMAND_HMAC_KEY, signed, command["hmac"])}
    except Exception:
        pass  # status/detail already describe failed authenticated verification
    return output

def tamper_copy(event_id: str) -> dict:
    original = raw_row(event_id)
    if not store.decrypt_and_verify_event(original)[0]:
        raise ValueError("The original row is already damaged; select an intact event")
    directory = store.DB_PATH.parent / "demonstrations"
    directory.mkdir(parents=True, exist_ok=True)
    destination = directory / ("tamper-copy-" + uuid.uuid4().hex + ".db")
    # sqlite backup includes committed WAL contents; copying just .db does not.
    with store._lock, store._connection() as source:
        target = sqlite3.connect(destination)
        try:
            source.backup(target)
            target.row_factory = sqlite3.Row
            selected = dict(target.execute("SELECT * FROM security_events WHERE event_id=?", (event_id,)).fetchone())
            before = store.decrypt_and_verify_event(selected)[0]
            altered = bytearray(selected["encrypted_payload"])
            altered[0] ^= 1
            with target:
                target.execute("UPDATE security_events SET encrypted_payload=? WHERE event_id=?", (bytes(altered), event_id))
            damaged = dict(target.execute("SELECT * FROM security_events WHERE event_id=?", (event_id,)).fetchone())
        finally:
            target.close()
    intact, _, detail = store.decrypt_and_verify_event(damaged)
    after = raw_row(event_id)
    unchanged = all(original[k] == after[k] for k in original)
    return {"copy_database": str(destination), "event_id": event_id, "before": "INTACT" if before else "TAMPERED",
            "after": "INTACT" if intact else "TAMPERED", "failure": detail,
            "original_unchanged": unchanged, "original_intact": store.decrypt_and_verify_event(after)[0],
            "original_first_byte": original["encrypted_payload"][0], "copy_first_byte": damaged["encrypted_payload"][0],
            "changed_bits": 1}
