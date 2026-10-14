"""
capture/pcap_analyzer.py

Offline, programmatic analysis of a saved PCAP file using PyShark, producing
a JSON forensic summary. This is the "perform programmatic PCAP analysis
using PyShark to drive detection logic automatically" functionality from
the synopsis — it complements the Gateway's own real-time, inline detection
(which does not need this file to run at all) by independently re-deriving
indicators of the same attack classes directly from the raw wire capture,
which is useful for (a) post-incident investigation, and (b) validating
that the Gateway's logged decisions match what actually happened on the
wire.

WHAT IT DETECTS FROM THE RAW CAPTURE ALONE
--------------------------------------------
  - traffic_by_source        packet/byte counts per source IP, per port
  - unauthorized_source_hits TCP SYNs to the Gateway's WCP port from an IP
                              not present in shared.config.AUTHORIZED_SOURCES
  - direct_modbus_hits       TCP SYNs to Device B's Modbus port from any IP
                              other than the configured Gateway host (a
                              network-layer sign of a malformed-modbus-direct
                              / bypass-the-gateway attempt, independent of
                              whether Device B's own frame parser rejected it)
  - duplicate_nonce_hits     WCP JSON payloads (parsed straight from the TCP
                              payload bytes) that reuse a nonce already seen
                              earlier in the capture — a network-layer replay
                              indicator, cross-checkable against the
                              Gateway's own replay_attack log entries
  - unparseable_wcp_payloads TCP payloads on the WCP port that are not valid
                              JSON at all — a network-layer malformed-request
                              indicator

The analyzer uses PyShark FileCapture and the same per-stream TCP
reassembler as the live detector. Retransmitted bytes are ignored, and
fragmented JSON is classified only after a complete command line exists.

USAGE
-----
    python3 -m capture.pcap_analyzer --pcap data/captures/waterguard_capture_20260101_120000.pcap
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config  # noqa: E402


def _extract_tcp_payload_bytes(packet) -> bytes | None:
    """
    PyShark exposes the raw TCP segment payload as a colon-separated hex
    string on packet.tcp.payload (for example, "7b:22:63:6c"). Returns None for
    packets with no payload (pure ACKs, SYNs, etc.) or where the field is
    unavailable for any reason -- this function must never raise, since a
    single malformed/incomplete packet must not abort the whole analysis.
    """
    try:
        # Prefer TShark's stream-reassembled payload so a WCP JSON line split
        # across TCP segments is analyzed once as a complete message.
        field = getattr(packet.tcp, "reassembled_data", None) or packet.tcp.payload
        hex_str = field.replace(":", "")
        return bytes.fromhex(hex_str)
    except (AttributeError, ValueError):
        return None


def analyze_pcap(pcap_path: Path, tshark_path: str | None = None) -> dict:
    import pyshark  # imported lazily so --help works without pyshark installed

    traffic_by_source: dict[str, dict[str, int]] = defaultdict(lambda: {"packets": 0, "bytes": 0})
    unauthorized_source_hits: list[dict] = []
    unauthenticated_modbus_hits: list[dict] = []
    direct_modbus_hits: list[dict] = []
    duplicate_nonce_hits: list[dict] = []
    unparseable_wcp_payloads: list[dict] = []

    from capture.live_monitor import LiveDetector
    detector = LiveDetector()
    authorized_ips = set(config.AUTHORIZED_SOURCES.values())
    seen_syn_streams = set()
    capture = pyshark.FileCapture(str(pcap_path), keep_packets=False, tshark_path=tshark_path)
    total_packets = 0
    try:
        for packet in capture:
            total_packets += 1
            try:
                if not hasattr(packet, "ip") or not hasattr(packet, "tcp"):
                    continue
                src_ip = str(packet.ip.src)
                dst_port = int(packet.tcp.dstport)
                key = f"{src_ip}:{dst_port}"
                traffic_by_source[key]["packets"] += 1
                traffic_by_source[key]["bytes"] += int(getattr(packet, "length", 0) or 0)
                syn = str(getattr(packet.tcp, "flags_syn", "0")) == "1"
                ack = str(getattr(packet.tcp, "flags_ack", "0")) == "1"
                syn_key = (str(packet.tcp.stream), src_ip, dst_port)
                if syn and not ack and syn_key not in seen_syn_streams:
                    seen_syn_streams.add(syn_key)
                    if dst_port == config.GATEWAY_WCP_PORT and src_ip not in authorized_ips:
                        unauthorized_source_hits.append({"src_ip":src_ip,"frame":int(packet.number)})
                # Share the live stream reassembler: split messages and TCP
                # retransmissions are not malformed commands or fresh replays.
                for indicator in detector.inspect_packet(packet):
                    hit = {"src_ip":src_ip,"frame":int(packet.number),"reason":indicator["reason"],
                           "tcp_stream":indicator["stream"]}
                    reason = indicator["reason"]
                    if reason == "pcap_unauthenticated_modbus":
                        unauthenticated_modbus_hits.append(hit)
                    elif reason == "pcap_direct_controller_connection":
                        direct_modbus_hits.append(hit)
                    elif reason == "pcap_replay_attack":
                        duplicate_nonce_hits.append(hit)
                    elif reason == "pcap_malformed_request":
                        unparseable_wcp_payloads.append(hit)
            except (AttributeError, ValueError, TypeError):
                continue
    finally:
        capture.close()

    return {
        "pcap_file": str(pcap_path),
        "total_packets": total_packets,
        "traffic_by_source_and_port": dict(traffic_by_source),
        "unauthorized_source_hits": unauthorized_source_hits,
        "unauthenticated_modbus_hits": unauthenticated_modbus_hits,
        "direct_modbus_hits": direct_modbus_hits,
        "duplicate_nonce_hits": duplicate_nonce_hits,
        "unparseable_wcp_payloads": unparseable_wcp_payloads,
        "summary": {
            "unauthorized_source_attempts": len(unauthorized_source_hits),
            "unauthenticated_modbus_attempts": len(unauthenticated_modbus_hits),
            "direct_modbus_bypass_attempts": len(direct_modbus_hits),
            "replay_indicators": len(duplicate_nonce_hits),
            "malformed_request_indicators": len(unparseable_wcp_payloads),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard offline PCAP analyzer (PyShark)")
    parser.add_argument("--pcap", required=True, help="path to a .pcap/.pcapng file")
    parser.add_argument("--output", default=None, help="write the JSON report here (default: <pcap>.analysis.json)")
    args = parser.parse_args()

    pcap_path = Path(args.pcap)
    if not pcap_path.exists():
        raise SystemExit(f"PCAP file not found: {pcap_path}")

    report = analyze_pcap(pcap_path)
    print(json.dumps(report, indent=2))

    out_path = Path(args.output) if args.output else pcap_path.with_suffix(pcap_path.suffix + ".analysis.json")
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nReport written to {out_path}")


if __name__ == "__main__":
    main()
