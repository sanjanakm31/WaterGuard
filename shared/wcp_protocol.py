"""
shared/wcp_protocol.py

Defines the WaterGuard Command Protocol (WCP) — the authenticated,
line-delimited JSON protocol spoken between untrusted clients (the
legitimate HMI client and the Device A attacker suite) and the WaterGuard
Gateway.

WHY A CUSTOM PROTOCOL INSTEAD OF RAW MODBUS FOR THIS LEG
---------------------------------------------------------
Modbus TCP has no native fields for authentication, so an HMAC tag cannot be
carried inside a standard Modbus PDU. WaterGuard therefore splits the system
into two segments:

    [ HMI / Attacker ] --WCP (authenticated JSON)--> [ Gateway ] --native Modbus TCP--> [ Device B ]

WCP is the untrusted-to-Gateway leg; native Modbus is used only on the
trusted Gateway-to-controller leg. This mirrors how real commercial OT
security gateways (e.g. unidirectional gateways / protocol-break firewalls)
front legacy, unauthenticated industrial protocols with an authenticated
proxy layer.

WIRE FORMAT
-----------
Each WCP message is exactly one line of JSON (UTF-8, terminated by "\n"),
sent over its own short-lived TCP connection (connect -> send one line ->
read one response line -> close). Fields:

    client_id  : str    -- registered identity of the sender (see
                           shared.config.AUTHORIZED_SOURCES)
    register   : int    -- target Modbus holding register (0-65535)
    value      : int    -- 16-bit unsigned value to write (0-65535)
    timestamp  : float  -- sender's UNIX time at message construction, used
                           for replay-window enforcement
    nonce      : str    -- random hex string, unique per message, used for
                           replay (duplicate-nonce) detection
    hmac       : str    -- hex HMAC-SHA256 over the canonical encoding of the
                           five fields above, keyed with the shared command key

The Gateway's response is also a single JSON line:
    {"decision": "ALLOW" | "BLOCK", "reason": "valid", "stage": "gateway", "event_id": "evt-1"}
"""

from __future__ import annotations

import json
import math
import socket

CANONICAL_FIELDS = ("client_id", "register", "value", "timestamp", "nonce")


class MalformedMessageError(Exception):
    """Raised whenever a received WCP message does not conform to the schema above."""


def build_canonical_payload(client_id: str, register: int, value: int, timestamp: float, nonce: str) -> dict:
    """Builds the exact five-field dict that gets HMAC-signed and later re-verified."""
    return {
        "client_id": client_id,
        "register": register,
        "value": value,
        "timestamp": timestamp,
        "nonce": nonce,
    }


def canonical_bytes(payload: dict) -> bytes:
    """
    Serializes exactly the five CANONICAL_FIELDS, in a fixed field order, to
    the byte string that is HMAC-signed / HMAC-verified. Using a fixed field
    order (rather than sort_keys on an arbitrary dict) guarantees the signer
    and verifier can never disagree on byte layout even if extra keys are
    present in the source dict.
    """
    try:
        ordered = {field: payload[field] for field in CANONICAL_FIELDS}
    except KeyError as exc:
        raise MalformedMessageError(f"missing field required for signing: {exc}") from exc
    return json.dumps(ordered, sort_keys=False, separators=(",", ":")).encode("utf-8")


def validate_schema(msg: object) -> None:
    """
    Strictly validates a parsed JSON value against the WCP schema. Raises
    MalformedMessageError with a human-readable reason on any violation.
    This function is intentionally pedantic: it is the Gateway's primary
    defense against malformed / fuzzed / type-confused input, so it must
    never itself raise an unhandled exception for ANY input (including
    non-dict JSON such as a bare list, number, or string).
    """
    if not isinstance(msg, dict):
        raise MalformedMessageError(f"top-level JSON value must be an object, got {type(msg).__name__}")

    for field in (*CANONICAL_FIELDS, "hmac"):
        if field not in msg:
            raise MalformedMessageError(f"missing required field '{field}'")

    allowed_fields = set(CANONICAL_FIELDS) | {"hmac"}
    unexpected = sorted(set(msg) - allowed_fields)
    if unexpected:
        raise MalformedMessageError(f"unexpected field(s): {', '.join(unexpected)}")

    client_id = msg["client_id"]
    if not isinstance(client_id, str) or not (1 <= len(client_id) <= 64):
        raise MalformedMessageError("'client_id' must be a string of length 1-64")

    register = msg["register"]
    if not isinstance(register, int) or isinstance(register, bool):
        raise MalformedMessageError("'register' must be an integer")
    if not (0 <= register <= 65535):
        raise MalformedMessageError("'register' must be in range 0-65535")

    value = msg["value"]
    if not isinstance(value, int) or isinstance(value, bool):
        raise MalformedMessageError("'value' must be an integer")
    if not (0 <= value <= 65535):
        raise MalformedMessageError("'value' must be in range 0-65535 (16-bit register width)")

    timestamp = msg["timestamp"]
    if not isinstance(timestamp, (int, float)) or isinstance(timestamp, bool):
        raise MalformedMessageError("'timestamp' must be numeric")
    if not math.isfinite(float(timestamp)):
        raise MalformedMessageError("'timestamp' must be finite")

    nonce = msg["nonce"]
    if not isinstance(nonce, str) or not (16 <= len(nonce) <= 64):
        raise MalformedMessageError("'nonce' must be a hex string of length 16-64")
    try:
        bytes.fromhex(nonce)
    except ValueError as exc:
        raise MalformedMessageError("'nonce' must be valid hexadecimal") from exc

    tag = msg["hmac"]
    if not isinstance(tag, str) or len(tag) != 64:
        raise MalformedMessageError("'hmac' must be a 64-character hex string (HMAC-SHA256)")
    try:
        bytes.fromhex(tag)
    except ValueError as exc:
        raise MalformedMessageError("'hmac' must be valid hexadecimal") from exc


def parse_wire_line(raw_line: bytes, max_bytes: int) -> dict:
    """
    Full parse pipeline for one line of wire data: size check -> UTF-8 decode
    -> JSON parse -> schema validation. Any failure raises
    MalformedMessageError with full diagnostic detail; callers must never let
    an exception from this function propagate as an unhandled server error.
    """
    if len(raw_line) == 0:
        raise MalformedMessageError("empty message")
    if len(raw_line) > max_bytes:
        raise MalformedMessageError(f"message of {len(raw_line)} bytes exceeds the {max_bytes} byte limit")
    try:
        text = raw_line.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MalformedMessageError(f"message is not valid UTF-8: {exc}") from exc
    try:
        msg = json.loads(text)
    except json.JSONDecodeError as exc:
        raise MalformedMessageError(f"invalid JSON: {exc}") from exc
    validate_schema(msg)
    return msg  # type: ignore[return-value]


def send_wcp_line(sock: socket.socket, obj: dict) -> None:
    """Serializes `obj` to one JSON line and writes it (plus trailing newline) to `sock`."""
    line = (json.dumps(obj, separators=(",", ":")) + "\n").encode("utf-8")
    sock.sendall(line)


def recv_wcp_line(sock: socket.socket, max_bytes: int, timeout: float = 5.0) -> bytes:
    """
    Reads bytes from `sock` until a newline is seen, EOF, or `max_bytes` is
    exceeded (in which case the caller's size check in parse_wire_line will
    reject the message). Returns the line WITHOUT the trailing newline.
    """
    sock.settimeout(timeout)
    buf = b""
    while b"\n" not in buf:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        if len(buf) > max_bytes:
            # Drain a bounded amount of the rest of this line before replying.
            # On Windows, closing a TCP connection while request bytes remain
            # unread can turn the intended JSON BLOCK response into WSAECONNRESET
            # at the client.  Keep only max_bytes+1 bytes (enough for the parser
            # to reject the message) and discard through the newline.
            oversized = buf[: max_bytes + 1]
            saw_newline = b"\n" in buf
            drained = len(buf)
            drain_limit = max_bytes * 16
            original_timeout = sock.gettimeout()
            try:
                sock.settimeout(min(timeout, 0.25))
                while not saw_newline and drained < drain_limit:
                    try:
                        remainder = sock.recv(min(4096, drain_limit - drained))
                    except socket.timeout:
                        break
                    if not remainder:
                        break
                    drained += len(remainder)
                    saw_newline = b"\n" in remainder
            finally:
                sock.settimeout(original_timeout)
            return oversized
    line, _, _ = buf.partition(b"\n")
    return line
