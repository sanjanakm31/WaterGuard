"""
gateway/waterguard_gateway.py

The WaterGuard Security Gateway: an inline enforcement point that sits
between untrusted WCP clients (the legitimate HMI client and Device A) and
the protected controller (Device B). It is NOT a passive monitor — every
message must pass all validation stages before it is forwarded as a real
Modbus write; anything that fails any stage is blocked before it can affect
the physical process.

VALIDATION PIPELINE (executed strictly in this order; the first failing
stage determines the block reason and short-circuits the remaining checks
— this is a deliberate "fail closed, fail fast" design):

    Stage 0  Wire/schema validation   -> reason: malformed_request
    Stage 1  Source validation        -> reasons: unauthorized_source, source_spoofing
    Stage 2  Freshness                -> reason: replay_attack
    Stage 3  HMAC-SHA256 authentication, then atomic nonce claim
                                      -> reasons: invalid_hmac, replay_attack
    Stage 4  Access control            -> reason: restricted_register
    Stage 5  Safety-bound validation   -> reason: unsafe_setpoint
    Decision  All stages passed -> forward the write to Device B; log ALLOW.

(See README.md for the full narrative rationale behind each stage.)

Every terminal outcome (every BLOCK and every ALLOW) is persisted through
gateway.evidence_store.record_event(), which hashes, HMAC-signs, and
AES-256-GCM-encrypts the record before writing it to SQLite. Each record's
`extra.processing_time_ms` field records the wall-clock time the Gateway
itself spent between "message fully received" and "decision made" — this is
what benchmarking/benchmark_gateway.py reads back to report internal
pipeline overhead separately from end-to-end network round-trip latency.
"""

from __future__ import annotations

import argparse
import json
import logging
import socket
import struct
import threading
import time
from typing import Optional

from controller.modbus_forwarder import LoopbackTestForwarder, ModbusForwarder, RealModbusForwarder
from gateway import evidence_store
from gateway.nonce_cache import NonceCache
from shared import config, crypto_utils
from shared.wcp_protocol import MalformedMessageError, canonical_bytes, parse_wire_line, recv_wcp_line, send_wcp_line

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] waterguard.gateway: %(message)s")
logger = logging.getLogger("waterguard.gateway")


class WaterGuardGateway:
    def __init__(self, forwarder: ModbusForwarder, host: Optional[str] = None, port: Optional[int] = None,
                 modbus_intake_port: Optional[int] = None):
        self.forwarder = forwarder
        self.host = host or config.GATEWAY_HOST
        self.port = port or config.GATEWAY_WCP_PORT
        self.modbus_intake_port = modbus_intake_port or config.GATEWAY_MODBUS_PORT
        self.nonce_cache = NonceCache(config.NONCE_CACHE_TTL_SECONDS)
        self._server_socket: Optional[socket.socket] = None
        self._modbus_socket: Optional[socket.socket] = None
        self._stop_event = threading.Event()
        self._accept_thread: Optional[threading.Thread] = None
        self._modbus_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #

    def start(self, blocking: bool = True) -> None:
        evidence_store.init_db()
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.host, self.port))
        self._server_socket.listen(64)
        logger.info("WaterGuard Gateway listening on %s:%d (WCP)", self.host, self.port)

        try:
            self._modbus_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._modbus_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._modbus_socket.bind((self.host, self.modbus_intake_port))
            self._modbus_socket.listen(32)
        except Exception:
            self._server_socket.close()
            raise
        logger.info(
            "Unauthenticated Modbus intake listening on %s:%d (fail-closed BLOCK only)",
            self.host, self.modbus_intake_port,
        )
        self._modbus_thread = threading.Thread(target=self._accept_modbus_loop, daemon=True)
        self._modbus_thread.start()

        if blocking:
            self._accept_loop()
        else:
            self._accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self._accept_thread.start()

    def _accept_loop(self) -> None:
        assert self._server_socket is not None
        try:
            while not self._stop_event.is_set():
                try:
                    self._server_socket.settimeout(1.0)
                    client_sock, addr = self._server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                thread = threading.Thread(target=self._handle_connection, args=(client_sock, addr), daemon=True)
                thread.start()
        finally:
            self._server_socket.close()

    def _accept_modbus_loop(self) -> None:
        assert self._modbus_socket is not None
        try:
            while not self._stop_event.is_set():
                try:
                    self._modbus_socket.settimeout(1.0)
                    client_sock, addr = self._modbus_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(
                    target=self._handle_raw_modbus_connection,
                    args=(client_sock, addr),
                    daemon=True,
                ).start()
        finally:
            try:
                self._modbus_socket.close()
            except OSError as exc:
                logger.debug("raw Modbus intake socket was already closed: %s", exc)

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket is not None:
            try:
                self._server_socket.shutdown(socket.SHUT_RDWR)
            except OSError as exc:
                logger.debug("WCP listener shutdown skipped: %s", exc)
            try:
                self._server_socket.close()
            except OSError as exc:
                logger.debug("WCP listener was already closed: %s", exc)
        if self._modbus_socket is not None:
            try:
                self._modbus_socket.shutdown(socket.SHUT_RDWR)
            except OSError as exc:
                logger.debug("raw Modbus listener shutdown skipped: %s", exc)
            try:
                self._modbus_socket.close()
            except OSError as exc:
                logger.debug("raw Modbus listener was already closed: %s", exc)
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=3.0)
        if self._modbus_thread is not None:
            self._modbus_thread.join(timeout=3.0)

    # ------------------------------------------------------------------ #
    # Per-connection handling
    # ------------------------------------------------------------------ #

    def _handle_connection(self, client_sock: socket.socket, addr: tuple) -> None:
        peer_ip = addr[0]
        stage_start = time.perf_counter()
        with client_sock:
            try:
                raw_line = recv_wcp_line(client_sock, config.MAX_WCP_MESSAGE_BYTES)
                if not raw_line:
                    return  # readiness probe or peer closed without sending a request
                # Measure validation after receipt. Network receive time and
                # evidence persistence are measured separately by client RTT.
                stage_start = time.perf_counter()
                self._process_message(raw_line, peer_ip, client_sock, stage_start)
            except Exception as exc:
                logger.exception("Unhandled error while servicing connection from %s", peer_ip)
                processing_time_ms = (time.perf_counter() - stage_start) * 1000.0
                event_id = evidence_store.record_event(
                    client_id=None,
                    peer_ip=peer_ip,
                    register=None,
                    value=None,
                    stage="internal",
                    decision="ERROR",
                    reason="internal_error",
                    extra={
                        "detail": type(exc).__name__,
                        "processing_time_ms": round(processing_time_ms, 4),
                    },
                )
                self._safe_respond(
                    client_sock,
                    {
                        "decision": "ERROR",
                        "reason": "internal_error",
                        "stage": "internal",
                        "event_id": event_id,
                    },
                )

    @staticmethod
    def _safe_respond(sock: socket.socket, response: dict) -> None:
        try:
            send_wcp_line(sock, response)
        except OSError as exc:
            logger.debug("client disconnected before WCP response: %s", exc)

    def _handle_raw_modbus_connection(self, client_sock: socket.socket, addr: tuple) -> None:
        """Fail closed for native Modbus arriving from the untrusted side.

        Modbus TCP has no field that can carry WaterGuard's HMAC envelope.
        Consequently, a native write presented to the gateway cannot be
        authenticated and is never forwarded. A standards-shaped Modbus
        exception response is returned when enough of the MBAP header is
        available, while the attempt is recorded as encrypted evidence.
        """
        peer_ip = addr[0]
        started = time.perf_counter()
        register = None
        value = None
        function_code = 0
        transaction_id = b"\x00\x00"
        protocol_id = b"\x00\x00"
        unit_id = 1
        detail = "native Modbus has no WaterGuard HMAC envelope"

        with client_sock:
            client_sock.settimeout(2.0)
            try:
                header = self._recv_exact(client_sock, 7)
                if not header:
                    return  # readiness probe or peer closed without a Modbus request
                if len(header) != 7:
                    detail = f"truncated Modbus MBAP header ({len(header)}/7 bytes)"
                else:
                    transaction_id, protocol_id, length, unit_id = struct.unpack(">2s2sHB", header)
                    if protocol_id != b"\x00\x00" or not (2 <= length <= 254):
                        detail = "invalid Modbus MBAP protocol identifier or length"
                    else:
                        pdu = self._recv_exact(client_sock, length - 1)
                        if pdu:
                            function_code = pdu[0]
                        if function_code == 6 and len(pdu) >= 5:
                            register, value = struct.unpack(">HH", pdu[1:5])
                            detail = (
                                f"unauthenticated native Modbus write-single-register request "
                                f"for register {register}, value {value}"
                            )
                        elif function_code == 16 and len(pdu) >= 5:
                            register = struct.unpack(">H", pdu[1:3])[0]
                            detail = f"unauthenticated native Modbus write-multiple-registers request at {register}"
                        else:
                            detail = f"unauthenticated native Modbus function {function_code}"
            except (OSError, struct.error) as exc:
                detail = f"malformed or incomplete native Modbus request: {exc}"

            processing_time_ms = (time.perf_counter() - started) * 1000.0
            event_id = evidence_store.record_event(
                client_id=None,
                peer_ip=peer_ip,
                register=register,
                value=value,
                stage="hmac_authentication",
                decision="BLOCK",
                reason="unauthenticated_modbus",
                extra={
                    "detail": detail,
                    "function_code": function_code,
                    "processing_time_ms": round(processing_time_ms, 4),
                },
            )
            logger.warning(
                "BLOCK raw Modbus peer=%s register=%s value=%s detail=%r event=%s",
                peer_ip, register, value, detail, event_id,
            )

            if function_code:
                exception_pdu = bytes([function_code | 0x80, 1])
                response = transaction_id + protocol_id + struct.pack(">H", 3) + bytes([unit_id]) + exception_pdu
                try:
                    client_sock.sendall(response)
                except OSError as exc:
                    logger.debug("client disconnected before Modbus exception response: %s", exc)

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        data = bytearray()
        while len(data) < size:
            chunk = sock.recv(size - len(data))
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    # ------------------------------------------------------------------ #
    # Validation pipeline
    # ------------------------------------------------------------------ #

    def _process_message(self, raw_line: bytes, peer_ip: str, client_sock: socket.socket, stage_start: float) -> None:
        names = ["schema", "source", "freshness", "hmac", "nonce", "access", "safety", "forwarding"]
        trace = [{"check": name, "status": "SKIPPED", "detail": "Not reached"} for name in names]
        msg = None

        def result(name, status, detail):
            trace[names.index(name)].update(status=status, detail=detail)

        def reject(check, stage, reason, detail):
            result(check, "FAIL", detail)
            self._reject(client_sock, (msg or {}).get("client_id"), peer_ip,
                         (msg or {}).get("register"), (msg or {}).get("value"), stage_start,
                         stage=stage, reason=reason, detail=detail,
                         decision="ERROR" if check == "forwarding" else "BLOCK",
                         proof={"validation_trace": trace, "command": msg,
                                "raw_preview": None if msg else raw_line[:512].decode("utf-8", errors="replace"),
                                "controller_forwarded": None if check == "forwarding" else False})

        try:
            msg = parse_wire_line(raw_line, config.MAX_WCP_MESSAGE_BYTES)
        except MalformedMessageError as exc:
            reject("schema", "schema_validation", "malformed_request", str(exc))
            return
        result("schema", "PASS", "Valid WCP JSON, exact fields/types/hex and message-size limit")
        client_id, register, value = msg["client_id"], msg["register"], msg["value"]
        timestamp, nonce = msg["timestamp"], msg["nonce"]
        expected_ip = config.AUTHORIZED_SOURCES.get(client_id)
        if expected_ip is None:
            reject("source", "source_validation", "unauthorized_source",
                   f"client_id '{client_id}' is not present in the authorized-source registry")
            return
        if expected_ip != peer_ip:
            reject("source", "source_validation", "source_spoofing",
                   f"client_id '{client_id}' is registered to {expected_ip}, but TCP peer is {peer_ip}")
            return
        result("source", "PASS", f"Observed TCP peer {peer_ip} matches the registry for {client_id}")
        now = time.time()
        age = abs(now - timestamp)
        if age > config.REPLAY_WINDOW_SECONDS:
            reject("freshness", "replay_validation", "replay_attack",
                   f"Timestamp difference {age:.3f}s exceeds {config.REPLAY_WINDOW_SECONDS}s")
            return
        result("freshness", "PASS", f"Absolute clock difference {age:.3f}s within {config.REPLAY_WINDOW_SECONDS}s")
        if not crypto_utils.hmac_verify(config.COMMAND_HMAC_KEY, canonical_bytes(msg), msg["hmac"]):
            reject("hmac", "hmac_authentication", "invalid_hmac", "HMAC-SHA256 constant-time comparison failed")
            return
        result("hmac", "PASS", "HMAC-SHA256 matches the canonical five-field command bytes")
        if self.nonce_cache.seen_before(client_id, nonce):
            reject("nonce", "replay_validation", "replay_attack", f"Nonce {nonce} already used by {client_id}")
            return
        result("nonce", "PASS", "Authenticated (client_id, nonce) atomically claimed; not previously used")
        if register not in config.WRITABLE_REGISTERS:
            reject("access", "access_control", "restricted_register", f"Register {register} is read-only or not a recognized writable register")
            return
        result("access", "PASS", f"Register {register} is a recognized writable register")
        low, high = config.SAFETY_BOUNDS[register]
        if not low <= value <= high:
            reject("safety", "safety_validation", "unsafe_setpoint", f"Value {value} outside configured raw bound [{low}, {high}]")
            return
        result("safety", "PASS", f"Value {value} within configured raw bound [{low}, {high}]")
        validation_time_ms = (time.perf_counter() - stage_start) * 1000
        forward_start = time.perf_counter()
        try:
            self.forwarder.write_register(register, value)
        except Exception as exc:
            reject("forwarding", "forwarding", "controller_unreachable", str(exc))
            return
        modbus_forward_time_ms = (time.perf_counter() - forward_start) * 1000
        result("forwarding", "PASS", "Protected controller acknowledged the Modbus TCP write")
        self._allow(client_sock, client_id, peer_ip, register, value, stage_start,
                    validation_time_ms=validation_time_ms, modbus_forward_time_ms=modbus_forward_time_ms,
                    proof={"validation_trace": trace, "command": msg, "controller_forwarded": True})

    # ------------------------------------------------------------------ #
    # Terminal outcomes (logging + evidence persistence + client response)
    # ------------------------------------------------------------------ #

    def _reject(self, sock, client_id, peer_ip, register, value, stage_start: float, *,
                stage: str, reason: str, detail: str, proof: Optional[dict] = None, decision: str = "BLOCK") -> None:
        processing_time_ms = (time.perf_counter() - stage_start) * 1000.0
        event_id = evidence_store.record_event(
            client_id=client_id, peer_ip=peer_ip, register=register, value=value,
            stage=stage, decision=decision, reason=reason,
            extra={
                "detail": detail,
                "processing_time_ms": round(processing_time_ms, 4),
                "timing_scope": "complete_WCP_message_to_rejection_before_evidence_storage",
                **(proof or {}),
            },
        )
        logger.warning(
            "%s  client=%s peer=%s register=%s value=%s stage=%s reason=%s detail=%r "
            "processing_ms=%.3f event=%s",
            decision, client_id, peer_ip, register, value, stage, reason, detail, processing_time_ms, event_id,
        )
        self._safe_respond(sock, {"decision": decision, "reason": reason, "stage": stage, "event_id": event_id})

    def _allow(self, sock, client_id, peer_ip, register, value, stage_start: float, *,
               validation_time_ms: float, modbus_forward_time_ms: float, proof: Optional[dict] = None) -> None:
        processing_time_ms = (time.perf_counter() - stage_start) * 1000.0
        event_id = evidence_store.record_event(
            client_id=client_id, peer_ip=peer_ip, register=register, value=value,
            stage="decision", decision="ALLOW", reason="all_checks_passed",
            extra={
                "processing_time_ms": round(processing_time_ms, 4),
                "validation_time_ms": round(validation_time_ms, 4),
                "modbus_forward_time_ms": round(modbus_forward_time_ms, 4),
                "timing_scope": "complete_WCP_message_to_controller_reply_before_evidence_storage",
                **(proof or {}),
            },
        )
        logger.info(
            "ALLOW  client=%s peer=%s register=%s value=%s processing_ms=%.3f event=%s",
            client_id, peer_ip, register, value, processing_time_ms, event_id,
        )
        self._safe_respond(sock, {"decision": "ALLOW", "reason": "all_checks_passed", "stage": "decision", "event_id": event_id})


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard Security Gateway")
    parser.add_argument("--modbus-host", default=config.CONTROLLER_HOST, help="Device B host (ignored with --test-mode)")
    parser.add_argument("--modbus-port", type=int, default=config.CONTROLLER_MODBUS_PORT, help="Device B port (ignored with --test-mode)")
    parser.add_argument("--wcp-port", type=int, default=config.GATEWAY_WCP_PORT)
    parser.add_argument("--modbus-intake-port", type=int, default=config.GATEWAY_MODBUS_PORT)
    parser.add_argument(
        "--test-mode", action="store_true",
        help="Use an in-memory LoopbackTestForwarder instead of a real Modbus controller "
             "(pipeline testing only — never use for the graded demo).",
    )
    args = parser.parse_args()

    forwarder: ModbusForwarder
    if args.test_mode:
        forwarder = LoopbackTestForwarder()
    else:
        forwarder = RealModbusForwarder(args.modbus_host, args.modbus_port)

    gateway = WaterGuardGateway(
        forwarder,
        port=args.wcp_port,
        modbus_intake_port=args.modbus_intake_port,
    )
    try:
        gateway.start()
    except KeyboardInterrupt:
        gateway.stop()


if __name__ == "__main__":
    main()
