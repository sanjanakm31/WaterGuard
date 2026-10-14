"""
capture/pcap_capture.py

Live network capture on the Gateway's WCP port and Device B's Modbus port,
using PyShark (a Python wrapper around tshark/Wireshark), written to a PCAP
file for forensic evidence and for offline analysis by
capture/pcap_analyzer.py. This satisfies the synopsis's "capture and
analyse network traffic using Wireshark/PyShark-based PCAP analysis"
requirement directly.

This module is a FORENSIC/ACCOUNTABILITY layer, complementary to — not a
replacement for — the Gateway's own real-time inline enforcement in
gateway/waterguard_gateway.py. The Gateway blocks attacks in real time
whether or not a capture is running; this module additionally preserves the
raw wire traffic so an investigator can independently re-derive what
happened, export it as tamper-evident evidence (see
tools/export_evidence_pcap.py), or feed it to capture/pcap_analyzer.py for
the automated summary report.

REQUIREMENTS AND PRIVILEGES
----------------------------
Requires `tshark` (the Wireshark CLI backend) installed at the OS level, in
addition to the `pyshark` Python package. Live capture on a network
interface typically requires either running as root/Administrator, or (on
Linux) granting the capture binary CAP_NET_RAW/CAP_NET_ADMIN:

    sudo apt install wireshark tshark
    sudo usermod -a -G wireshark $USER      # log out/in after this
    # or, to avoid running Python itself as root:
    sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which dumpcap))

Run this short, low-traffic check after installing Wireshark/TShark:
    python3 -m capture.pcap_capture --interface lo --duration 10
It creates a capture plus an automated `.analysis.json` detection report.

USAGE
-----
    python3 -m capture.pcap_capture --interface eth0
    python3 -m capture.pcap_capture --interface lo --duration 60   # time-boxed run
"""

from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config  # noqa: E402

CAPTURE_DIR = Path(__file__).resolve().parent.parent / "data" / "captures"


def build_bpf_filter() -> str:
    """
    Captures only the two ports WaterGuard cares about: the Gateway's WCP
    port (client <-> Gateway traffic) and Device B's Modbus port (Gateway
    <-> controller traffic, and — if network segmentation is misconfigured
    or being deliberately tested via malformed-modbus-direct — anyone else
    reaching Device B directly).
    """
    return (
        f"tcp port {config.GATEWAY_WCP_PORT} or "
        f"tcp port {config.GATEWAY_MODBUS_PORT} or "
        f"tcp port {config.CONTROLLER_MODBUS_PORT}"
    )


def run_capture(interface: str, duration_seconds: int | None, output_path: Path) -> None:
    import pyshark  # imported lazily so --help works without pyshark installed

    output_path.parent.mkdir(parents=True, exist_ok=True)
    bpf = build_bpf_filter()
    print(f"[pcap_capture] interface={interface} filter='{bpf}' -> {output_path}")

    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf, output_file=str(output_path))

    packet_count = 0
    try:
        if duration_seconds:
            capture.sniff(timeout=duration_seconds)
            packet_count = len(capture)
        else:
            for _ in capture.sniff_continuously():
                packet_count += 1
                if packet_count % 50 == 0:
                    print(f"[pcap_capture] {packet_count} packets captured so far")
    except KeyboardInterrupt:
        print("\n[pcap_capture] stopped by user")
    finally:
        capture.close()

    print(f"[pcap_capture] done — {packet_count} packet(s) written to {output_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard live PCAP capture (PyShark/tshark)")
    parser.add_argument("--interface", required=True, help="e.g. eth0, lo, or an adapter GUID on Windows")
    parser.add_argument("--duration", type=int, default=None, help="seconds; omit to capture until Ctrl+C")
    parser.add_argument("--output", default=None, help="output .pcap path (default: timestamped, under data/captures/)")
    parser.add_argument("--no-analyze", action="store_true", help="skip the automatic PyShark forensic analysis after capture")
    args = parser.parse_args()

    if args.output:
        output_path = Path(args.output)
    else:
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = CAPTURE_DIR / f"waterguard_capture_{stamp}.pcap"

    run_capture(args.interface, args.duration, output_path)
    if not args.no_analyze:
        from capture.pcap_analyzer import analyze_pcap

        report = analyze_pcap(output_path)
        report_path = output_path.with_suffix(output_path.suffix + ".analysis.json")
        report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[pcap_capture] automated detection report -> {report_path}")


if __name__ == "__main__":
    main()
