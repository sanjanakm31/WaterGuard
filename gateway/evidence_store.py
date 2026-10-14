"""
gateway/evidence_store.py

Persists every security event (every ALLOW and every BLOCK decision the
Gateway makes) as a tamper-evident record in a local SQLite database.

Pipeline for each record, exactly matching the synopsis's stated design:

    1. Build the event as a plain dict.
    2. Serialize it deterministically  -> canonical JSON bytes.
    3. SHA-256 hash the canonical JSON -> payload_hash.
    4. HMAC-SHA256-sign payload_hash under EVIDENCE_HMAC_KEY -> hash_hmac.
    5. AES-256-GCM-encrypt the canonical JSON under EVIDENCE_AES_KEY
       -> (aes_nonce, encrypted_payload).
    6. Store: event_id, ts, client_id, peer_ip, stage, decision, reason
       (all in the clear, so the dashboard can query/filter without
       decrypting anything) plus payload_hash, hash_hmac, aes_nonce,
       encrypted_payload.

`decrypt_and_verify_event()` reverses this and is the basis of
tools/verify_evidence_integrity.py, which independently re-derives the hash
and HMAC from the decrypted plaintext and flags any row where they do not
match what is stored — this is the project's deliberate tamper-evidence
verification capability.
"""

from __future__ import annotations

import json
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator
from typing import Any, Optional

from shared import config, crypto_utils

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "waterguard_evidence.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS security_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            TEXT NOT NULL UNIQUE,
    ts                  REAL NOT NULL,
    client_id           TEXT,
    peer_ip             TEXT,
    stage               TEXT NOT NULL,
    decision            TEXT NOT NULL,
    reason              TEXT NOT NULL,
    payload_hash        TEXT NOT NULL,
    hash_hmac           TEXT NOT NULL,
    aes_nonce           BLOB NOT NULL,
    encrypted_payload   BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(ts);
CREATE INDEX IF NOT EXISTS idx_security_events_decision ON security_events(decision);
"""

SCHEMA_VERSION = 1

_lock = threading.Lock()


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    """Yield a transactional connection and always close its OS handle.

    ``sqlite3.Connection`` commits/rolls back when used as a context manager,
    but it does not close itself afterwards.  Closing explicitly is essential
    on Windows, where an open handle prevents temporary database files from
    being deleted after tests and backups.
    """
    conn = _connect()
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def init_db() -> None:
    with _lock, _connection() as conn:
        conn.executescript(_SCHEMA)
        current = conn.execute("PRAGMA user_version").fetchone()[0]
        if current > SCHEMA_VERSION:
            raise RuntimeError(
                f"evidence database schema version {current} is newer than this application supports ({SCHEMA_VERSION})"
            )
        # Version 1 is the baseline schema. Future releases add ordered,
        # transactional migrations here before advancing user_version.
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")


def record_event(
    *,
    client_id: Optional[str],
    peer_ip: Optional[str],
    register: Optional[int],
    value: Optional[int],
    stage: str,
    decision: str,
    reason: str,
    extra: Optional[dict[str, Any]] = None,
) -> str:
    """
    Builds and persists one tamper-evident security-event record. Returns the
    generated event_id (also embedded inside the encrypted payload itself,
    so the two can be cross-checked).
    """
    event_id = str(uuid.uuid4())
    record = {
        "event_id": event_id,
        "ts": time.time(),
        "client_id": client_id,
        "peer_ip": peer_ip,
        "register": register,
        "value": value,
        "stage": stage,
        "decision": decision,
        "reason": reason,
        "extra": extra or {},
    }

    payload_bytes = crypto_utils.canonical_json(record)
    payload_hash = crypto_utils.sha256_hex(payload_bytes)
    hash_hmac = crypto_utils.hmac_sha256_hex(config.EVIDENCE_HMAC_KEY, payload_hash.encode("utf-8"))
    aes_nonce, encrypted_payload = crypto_utils.aes_gcm_encrypt(config.EVIDENCE_AES_KEY, payload_bytes)

    with _lock, _connection() as conn:
        conn.execute(
            """
            INSERT INTO security_events
                (event_id, ts, client_id, peer_ip, stage, decision, reason,
                 payload_hash, hash_hmac, aes_nonce, encrypted_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id, record["ts"], client_id, peer_ip, stage, decision, reason,
                payload_hash, hash_hmac, aes_nonce, encrypted_payload,
            ),
        )
    return event_id


def fetch_recent_events(limit: int = 100) -> list[dict[str, Any]]:
    """
    Returns the most recent `limit` events after decrypting and verifying
    every row. Intact rows come from the signed payload, never from mutable
    display columns. A failed row is reduced to a TAMPERED alert so the
    dashboard cannot accidentally present modified metadata as authentic.
    """
    with _lock, _connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """
            SELECT *
            FROM security_events ORDER BY ts DESC LIMIT ?
            """,
            (limit,),
        ).fetchall()
    verified_events: list[dict[str, Any]] = []
    for sql_row in rows:
        row = dict(sql_row)
        intact, record, detail = decrypt_and_verify_event(row)
        if intact and record is not None:
            verified_events.append({
                "id": row["id"],
                **record,
                "integrity_status": "INTACT",
            })
        else:
            # Do not present mutable cleartext columns as trusted event data.
            verified_events.append({
                "id": row["id"],
                "event_id": row["event_id"],
                "ts": row["ts"],
                "client_id": None,
                "peer_ip": None,
                "stage": "integrity_verification",
                "decision": "TAMPERED",
                "reason": detail,
                "register": None,
                "value": None,
                "extra": {},
                "integrity_status": "TAMPERED",
            })
    return verified_events


def fetch_all_raw_rows() -> list[dict[str, Any]]:
    """
    Returns every column (including the cryptographic material) for every
    row, ordered by primary key. Used by tools/verify_evidence_integrity.py.
    """
    with _lock, _connection() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM security_events ORDER BY id ASC").fetchall()
    return [dict(row) for row in rows]


def decrypt_and_verify_event(row: dict[str, Any]) -> tuple[bool, Optional[dict], str]:
    """
    Given one raw row (as returned by fetch_all_raw_rows), independently
    re-derives and checks every layer of protection:

        1. AES-256-GCM decryption (the GCM tag itself already authenticates
           the ciphertext — a single flipped bit anywhere in the ciphertext,
           nonce, or associated data causes decryption to fail outright).
        2. Recompute SHA-256 of the decrypted plaintext and compare to the
           stored payload_hash.
        3. Recompute HMAC-SHA256 of the stored payload_hash and compare to
           the stored hash_hmac (this catches the edge case where an
           attacker with write access to the database swaps BOTH the
           ciphertext and the stored hash consistently, but does not also
           possess EVIDENCE_HMAC_KEY to re-sign the swapped hash).

    Returns (is_intact, decrypted_record_or_None, detail_message).
    """
    try:
        plaintext = crypto_utils.aes_gcm_decrypt(
            config.EVIDENCE_AES_KEY, bytes(row["aes_nonce"]), bytes(row["encrypted_payload"])
        )
    except Exception as exc:
        return False, None, f"AES-256-GCM authentication failed (ciphertext tampered or corrupted): {exc!r}"

    recomputed_hash = crypto_utils.sha256_hex(plaintext)
    if recomputed_hash != row["payload_hash"]:
        return False, None, (
            f"SHA-256 mismatch — stored payload_hash={row['payload_hash']} "
            f"recomputed={recomputed_hash} (decrypted content does not match its recorded hash)"
        )

    if not crypto_utils.hmac_verify(
        config.EVIDENCE_HMAC_KEY, row["payload_hash"].encode("utf-8"), row["hash_hmac"]
    ):
        return False, None, "HMAC-SHA256 verification of the stored hash failed (hash_hmac field tampered)"

    try:
        record = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return False, None, f"Decrypted payload is not valid JSON: {exc!r}"

    if record.get("event_id") != row["event_id"]:
        return False, None, (
            f"event_id mismatch — column says {row['event_id']!r}, "
            f"decrypted payload says {record.get('event_id')!r}"
        )

    # These columns are duplicated in cleartext for indexed dashboard
    # queries. Cross-check every duplicate so a database editor cannot alter
    # what operators see while leaving the encrypted record untouched.
    for field in ("ts", "client_id", "peer_ip", "stage", "decision", "reason"):
        if record.get(field) != row[field]:
            return False, None, (
                f"cleartext column mismatch for {field!r}: column={row[field]!r}, "
                f"signed payload={record.get(field)!r}"
            )

    return True, record, "OK"
