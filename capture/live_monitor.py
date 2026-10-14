"""Live PyShark detection, independent of the gateway's inline prevention.

The gateway rejects bad writes synchronously. This observer independently
classifies captured traffic and stores encrypted ALERT events immediately.
An ALERT is a traffic observation, never a claim that the observer blocked
a packet. The original TShark recorder remains the source of the PCAP export.
"""
from __future__ import annotations

import argparse
from collections import OrderedDict
from dataclasses import dataclass, field
import signal
import time

from gateway import evidence_store
from gateway.nonce_cache import NonceCache
from shared import config, crypto_utils
from shared.wcp_protocol import MalformedMessageError, canonical_bytes, parse_wire_line
from capture.pcap_capture import build_bpf_filter


@dataclass
class LineBuffer:
    """Reassemble one WCP line, ignoring retransmissions within a TCP stream."""
    expected: int | None = None
    data: bytearray = field(default_factory=bytearray)
    pending: dict[int, bytes] = field(default_factory=dict)
    finished: bool = False
    last_seen: float = 0.0

    def feed(self, sequence: int, payload: bytes) -> bytes | None:
        if self.finished or not payload:
            return None
        if self.expected is None:
            self.expected = sequence
        if sequence + len(payload) <= self.expected:
            return None
        self.pending[sequence] = payload
        if len(self.pending) > 32 or sum(map(len, self.pending.values())) > 65536:
            self.finished = True
            self.pending.clear()
            return b"x" * (config.MAX_WCP_MESSAGE_BYTES + 1)
        while self.pending:
            start = min(self.pending)
            if start > self.expected:
                break  # wait for an out-of-order gap to arrive
            chunk = self.pending.pop(start)
            unseen = chunk[max(0, self.expected - start):]
            self.data.extend(unseen)
            self.expected += len(unseen)
            if b"\n" in self.data or len(self.data) > config.MAX_WCP_MESSAGE_BYTES:
                self.finished = True
                line = bytes(self.data).split(b"\n", 1)[0]
                self.data.clear()
                self.pending.clear()
                return line
        return None


class LiveDetector:
    """Bounded per-stream state; capture results do not modify gateway policy."""

    def __init__(self):
        self.streams: OrderedDict[str, LineBuffer] = OrderedDict()
        self.nonces = NonceCache(config.NONCE_CACHE_TTL_SECONDS)

    def inspect_command(self, raw: bytes, peer_ip: str, captured_at: float) -> dict | None:
        try:
            message = parse_wire_line(raw, config.MAX_WCP_MESSAGE_BYTES)
        except (MalformedMessageError, ValueError, OverflowError) as exc:
            return {"reason": "pcap_malformed_request", "detail": str(exc)}
        result = {key: message[key] for key in ("client_id", "register", "value")}
        expected_ip = config.AUTHORIZED_SOURCES.get(message["client_id"])
        if expected_ip is None:
            reason = "unauthorized_source"
        elif expected_ip != peer_ip:
            reason = "source_spoofing"
        elif abs(captured_at - message["timestamp"]) > config.REPLAY_WINDOW_SECONDS:
            reason = "replay_attack"
        elif not crypto_utils.hmac_verify(
            config.COMMAND_HMAC_KEY, canonical_bytes(message), message["hmac"]
        ):
            reason = "invalid_hmac"
        elif self.nonces.seen_before(message["client_id"], message["nonce"]):
            reason = "replay_attack"
        elif message["register"] not in config.WRITABLE_REGISTERS:
            reason = "restricted_register"
        else:
            low, high = config.SAFETY_BOUNDS[message["register"]]
            if low <= message["value"] <= high:
                return None
            reason = "unsafe_setpoint"
        return {**result, "reason": "pcap_" + reason}

    def inspect_packet(self, packet) -> list[dict]:
        try:
            peer_ip = str(packet.ip.src)
            destination = int(packet.tcp.dstport)
            captured_at = float(packet.sniff_timestamp)
            stream = str(packet.tcp.stream)
            sequence = int(packet.tcp.seq)
            is_syn = str(getattr(packet.tcp, "flags_syn", "0")) == "1"
            is_ack = str(getattr(packet.tcp, "flags_ack", "0")) == "1"
            raw_payload = getattr(packet.tcp, "payload", "")
            payload = bytes.fromhex(str(raw_payload).replace(":", "")) if raw_payload else b""
        except (AttributeError, ValueError, TypeError):
            return []

        metadata = {
            "peer_ip": peer_ip,
            "captured_at": captured_at,
            "frame": str(getattr(packet, "number", "unknown")),
            "stream": stream,
        }
        if destination == config.CONTROLLER_MODBUS_PORT:
            if is_syn and not is_ack and peer_ip != config.GATEWAY_TRUSTED_IP:
                return [{**metadata, "reason": "pcap_direct_controller_connection"}]
            return []
        if destination not in {config.GATEWAY_WCP_PORT, config.GATEWAY_MODBUS_PORT}:
            return []

        # Client-to-server traffic only. Stream IDs distinguish a true replay
        # on a new connection from duplicate capture/TCP retransmission bytes.
        key = f"{stream}:{peer_ip}:{destination}"
        while self.streams and (
            len(self.streams) >= 2048
            or captured_at - next(iter(self.streams.values())).last_seen > 30
        ):
            self.streams.popitem(last=False)
        state = self.streams.setdefault(key, LineBuffer())
        state.last_seen = captured_at
        self.streams.move_to_end(key)
        if is_syn and not is_ack and state.expected is None:
            state.expected = sequence + 1
        if destination == config.GATEWAY_MODBUS_PORT:
            if payload and not state.finished:
                state.finished = True
                return [{**metadata, "reason": "pcap_unauthenticated_modbus"}]
            return []

        line = state.feed(sequence, payload)
        if line is None:
            return []
        indicator = self.inspect_command(line, peer_ip, captured_at)
        return [{**metadata, **indicator}] if indicator else []


def record_indicator(indicator: dict) -> str:
    observed = time.time()
    return evidence_store.record_event(
        client_id=indicator.get("client_id"), peer_ip=indicator["peer_ip"],
        register=indicator.get("register"), value=indicator.get("value"),
        stage="live_pcap_analysis", decision="ALERT", reason=indicator["reason"],
        extra={
            "captured_at": indicator["captured_at"],
            "observed_at": observed,
            "capture_to_analysis_ms": round(max(0, observed - indicator["captured_at"]) * 1000, 4),
            "frame": indicator["frame"], "tcp_stream": indicator["stream"],
            "detail": indicator.get("detail", "independent live packet observation"),
            "enforcement": "gateway independently validates and blocks commands before forwarding",
        },
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard live PyShark detector")
    parser.add_argument("--interfaces", nargs="+", required=True)
    parser.add_argument("--tshark-path", required=True)
    args = parser.parse_args()
    import pyshark

    def interrupt(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupt)
    if hasattr(signal, "SIGBREAK"):
        signal.signal(signal.SIGBREAK, interrupt)
    evidence_store.init_db()
    detector = LiveDetector()
    capture = pyshark.LiveCapture(
        interface=args.interfaces,
        bpf_filter=build_bpf_filter(),
        tshark_path=args.tshark_path,
        custom_parameters=["-n"],
    )
    print("Live PyShark detector starting on " + ", ".join(args.interfaces), flush=True)
    try:
        for packet in capture.sniff_continuously():
            for indicator in detector.inspect_packet(packet):
                event_id = record_indicator(indicator)
                print(f"ALERT {indicator['reason']} event={event_id}", flush=True)
    except KeyboardInterrupt:
        pass
    finally:
        capture.close()


if __name__ == "__main__":
    main()
