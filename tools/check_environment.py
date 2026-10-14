"""Check installed software and optionally exercise actual capture permissions.

Does not print keys, replace configuration, modify a firewall, or start the
water process. Run from the project folder after installing requirements.txt.
"""
from __future__ import annotations

import argparse
import importlib
from importlib import metadata
from pathlib import Path
import re
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description="Check WaterGuard installation")
    parser.add_argument("--capture-test", action="store_true", help="perform a one-second packet capture")
    parser.add_argument("--capture-interface", default="auto", help="one capture interface, default loopback")
    parser.add_argument("--skip-capture", action="store_true", help="check only the core Python dependencies")
    args = parser.parse_args()
    if args.skip_capture and args.capture_test:
        parser.error("--capture-test and --skip-capture cannot be combined")
    errors = []
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    if sys.version_info < (3, 12):
        errors.append("Use Python 3.12 or newer; the supplied Windows setup selects Python 3.12.")
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Za-z0-9_-]+)(?:\[[^]]+\])?==([^\s]+)", line.strip())
        if not match:
            continue
        package, expected = match.groups()
        if args.skip_capture and package == "pyshark":
            continue
        try:
            actual = metadata.version(package)
            print(f"{package}: {actual}")
            if actual != expected:
                errors.append(f"{package}: expected {expected}, found {actual}; install requirements.txt.")
        except metadata.PackageNotFoundError:
            errors.append(f"{package}: missing; run python -m pip install -r requirements.txt")
    modules = ["pymodbus", "cryptography", "fastapi", "uvicorn", "pytest", "sqlite3"]
    if not args.skip_capture:
        modules.append("pyshark")
    for name in modules:
        try:
            importlib.import_module(name)
        except Exception as exc:
            errors.append(f"{name} import failed: {exc}")
    if not errors:
        try:
            from shared import config
            print("Configuration: all three key lengths validated (keys not printed).")
            print(f"Controller destination: {config.CONTROLLER_HOST}:{config.CONTROLLER_MODBUS_PORT}")
        except Exception as exc:
            errors.append(f"Configuration: {exc}")
    if not errors and not args.skip_capture:
        try:
            from capture.managed_capture import choose_capture_interface, find_tshark
            tshark = find_tshark()
            interface = choose_capture_interface(tshark, args.capture_interface)
            print(f"TShark: {tshark}")
            print(f"Capture interface: {interface}")
            if args.capture_test:
                from capture.pcap_capture import build_bpf_filter
                import pyshark
                with tempfile.TemporaryDirectory(prefix="waterguard_check_") as folder:
                    output = Path(folder) / "check.pcapng"
                    result = subprocess.run(
                        [tshark, "-i", interface, "-f", build_bpf_filter(),
                         "-a", "duration:1", "-w", str(output), "-q"],
                        capture_output=True, text=True, timeout=15,
                    )
                    if result.returncode != 0:
                        raise RuntimeError(result.stderr.strip() or "capture failed")
                    capture = pyshark.FileCapture(str(output), keep_packets=False, tshark_path=tshark)
                    try:
                        count = sum(1 for _packet in capture)
                    finally:
                        capture.close()
                    print(f"Capture and PyShark parsing: PASS ({count} packets; zero is normal before startup).")
        except Exception as exc:
            errors.append(f"Packet capture: {exc}")
    if errors:
        print("\nINSTALLATION IS NOT READY:")
        for error in errors:
            print("  - " + error)
        return 1
    print("\nINSTALLATION CHECK PASSED. This does not replace the live two-device demonstration.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
