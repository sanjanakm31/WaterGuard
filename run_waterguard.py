"""One-command launcher for the complete local WaterGuard demonstration."""

from __future__ import annotations

import argparse
import json
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.request
import webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
_runtime_warning_at = float("-inf")

def write_runtime_status(capture, state: str) -> bool:
    """Publish a complete snapshot without making telemetry a shutdown trigger.

    Windows can deny replacing a file while a dashboard reader or scanner has
    it open. Retry briefly, then keep the last complete snapshot. The health
    endpoint already reports snapshots older than five seconds as unknown.
    """
    global _runtime_warning_at
    directory = ROOT / "data"
    running = state == "running"
    status = {"updated_at": time.time(), "state": state,
              "capture_recorder_active": bool(running and capture and capture._process and capture._process.poll() is None),
              "capture_detector_active": bool(running and capture and capture._monitor_process and capture._monitor_process.poll() is None),
              "capture_interface": capture.interface if capture else None,
              "capture_file": str(capture.output_path) if capture else None}
    target = directory / "presentation_runtime.json"
    temporary = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        # Close this unique temporary file before replacement on Windows.
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                dir=directory, prefix="presentation_runtime-", suffix=".tmp",
                delete=False) as handle:
            temporary = Path(handle.name)
            json.dump(status, handle)
        for attempt in range(6):
            try:
                temporary.replace(target)
                return True
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.05 * (attempt + 1))
    except OSError as exc:
        now = time.monotonic()
        if state != "running" or now - _runtime_warning_at >= 30:
            print(f"LIVE STATUS WARNING: snapshot could not be refreshed: {exc}. "
                  "The command gateway is not stopped by this telemetry error.",
                  file=sys.stderr)
            _runtime_warning_at = now
        return False
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                # A scanner can also hold the temporary file briefly.
                pass


def ensure_configuration() -> None:
    if not ENV_FILE.exists():
        ENV_FILE.write_text(
            "\n".join([
                f"WG_COMMAND_HMAC_KEY={secrets.token_hex(32)}",
                f"WG_EVIDENCE_HMAC_KEY={secrets.token_hex(32)}",
                f"WG_EVIDENCE_AES_KEY={secrets.token_hex(32)}",
                "WG_AUTHORIZED_SOURCES=hmi-01=127.0.0.1",
                "WG_CONTROLLER_HOST=127.0.0.1",
                "WG_CONTROLLER_MODBUS_PORT=5502",
                "WG_GATEWAY_TRUSTED_IP=127.0.0.1",
                "WG_GATEWAY_HOST=0.0.0.0",
                "WG_GATEWAY_WCP_PORT=6000",
                "WG_GATEWAY_MODBUS_PORT=1502",
                "WG_DASHBOARD_HOST=0.0.0.0",
                "WG_DASHBOARD_PORT=8443",
                "WG_CAPTURE_INTERFACE=auto",
                "WG_REPLAY_WINDOW_SECONDS=5.0",
                "WG_NONCE_CACHE_TTL_SECONDS=120.0",
                "",
            ]),
            encoding="utf-8",
        )


def wait_for_port(host: str, port: int, name: str, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.4):
                return
        except OSError:
            time.sleep(0.15)
    raise RuntimeError(f"{name} did not start on {host}:{port} within {timeout:.0f} seconds")


def wait_for_dashboard(port: int, timeout: float = 20.0) -> None:
    """Wait until the HTTPS dashboard is serving its API, not merely listening."""
    deadline = time.monotonic() + timeout
    tls_context = ssl._create_unverified_context()
    url = f"https://127.0.0.1:{port}/api/state"
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, context=tls_context, timeout=1.0) as response:
                if response.status == 200:
                    return
        except Exception as exc:
            last_error = exc
            time.sleep(0.2)
    raise RuntimeError(f"HTTPS dashboard did not become ready within {timeout:.0f} seconds: {last_error}")


def start_component(module: str, *args: str) -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-m", module, *args], cwd=ROOT)


def stop_components(processes: list[subprocess.Popen]) -> None:
    for process in reversed(processes):
        if process.poll() is None:
            process.terminate()
    for process in reversed(processes):
        if process.poll() is None:
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()


def run_demo_commands() -> None:
    from attacker.device_a_attacker import (
        attack_command_forgery,
        attack_replay,
        attack_restricted_register,
        attack_unauthenticated_modbus,
        attack_unauthorized_source,
        attack_unsafe_setpoint,
    )
    from client.legit_hmi_client import send_command
    from shared import config

    host, port = "127.0.0.1", config.GATEWAY_WCP_PORT
    checks = [
        ("legitimate valve command", send_command("hmi-01", 1, 55, gateway_host=host, gateway_port=port)),
        ("legitimate chlorine command", send_command("hmi-01", 0, 180, gateway_host=host, gateway_port=port)),
        ("unauthorized client attack", attack_unauthorized_source(host, port)),
        ("forged command attack", attack_command_forgery(host, port)),
        ("unsafe setpoint attack", attack_unsafe_setpoint(host, port)),
        ("read-only register attack", attack_restricted_register(host, port)),
        (
            "unauthenticated native Modbus attack",
            attack_unauthenticated_modbus(host, config.GATEWAY_MODBUS_PORT),
        ),
        ("replay attack", attack_replay(host, port)),
    ]
    print("\nWaterGuard demonstration results:")
    for name, result in checks:
        print(f"  {name}: {result}")


def main() -> int:
    # The graphical Windows launcher sends Ctrl+Break for graceful shutdown.
    # Run the existing finally block so captures are closed and exported.
    import signal
    if hasattr(signal, "SIGBREAK"):
        def on_break(signum, frame):
            raise KeyboardInterrupt
        signal.signal(signal.SIGBREAK, on_break)
    parser = argparse.ArgumentParser(description="Start the complete local WaterGuard stack")
    parser.add_argument("--no-browser", action="store_true", help="do not open the HTTPS dashboard automatically")
    parser.add_argument("--no-demo", action="store_true", help="start services without sending sample normal/attack traffic")
    parser.add_argument(
        "--no-capture",
        action="store_true",
        help="explicitly disable automatic PCAP capture, analysis, and protected export",
    )
    parser.add_argument(
        "--capture-interface",
        default=None,
        help="TShark interface name, or comma-separated names for LAN plus loopback; "
             "defaults to WG_CAPTURE_INTERFACE or automatic loopback selection",
    )
    args = parser.parse_args()

    ensure_configuration()
    sys.path.insert(0, str(ROOT))
    from shared import config
    from tools.generate_tls_cert import CERT_PATH, KEY_PATH, generate

    if not CERT_PATH.exists() or not KEY_PATH.exists():
        generate()

    processes: list[subprocess.Popen] = []
    managed_capture = None
    exit_code = 0
    try:
        if not args.no_capture:
            from capture.managed_capture import ManagedCapture

            managed_capture = ManagedCapture(args.capture_interface or config.CAPTURE_INTERFACE)
            managed_capture.start()
        processes.append(start_component("controller.device_b_controller"))
        wait_for_port("127.0.0.1", config.CONTROLLER_MODBUS_PORT, "Device B")
        processes.append(start_component("gateway.waterguard_gateway"))
        wait_for_port("127.0.0.1", config.GATEWAY_WCP_PORT, "Security Gateway")
        wait_for_port("127.0.0.1", config.GATEWAY_MODBUS_PORT, "Gateway Modbus blocker")
        processes.append(start_component("dashboard.app"))
        wait_for_port("127.0.0.1", config.DASHBOARD_PORT, "HTTPS dashboard")
        wait_for_dashboard(config.DASHBOARD_PORT)

        if not args.no_demo:
            run_demo_commands()
        url = f"https://localhost:{config.DASHBOARD_PORT}/"
        print(f"\nWATERGUARD IS READY. Dashboard: {url}")
        print("Keep this terminal open while using the dashboard.")
        print("Use HTTPS and include port 8443. A self-signed certificate warning is expected.")
        print("Press Ctrl+C only when you want to stop WaterGuard.\n")
        if not args.no_browser:
            webbrowser.open(url)
        next_status = 0.0
        while all(process.poll() is None for process in processes):
            if managed_capture is not None:
                managed_capture.ensure_running()
            if time.monotonic() >= next_status:
                write_runtime_status(managed_capture, "running")
                next_status = time.monotonic() + 2
            time.sleep(0.5)
        failed = next(process for process in processes if process.poll() is not None)
        raise RuntimeError(f"a WaterGuard component exited unexpectedly with code {failed.returncode}")
    except KeyboardInterrupt:
        print("\nStopping WaterGuard")
    except Exception as exc:
        print(f"\nSTARTUP ERROR: {exc}", file=sys.stderr)
        exit_code = 1
    finally:
        stop_components(processes)
        if managed_capture is not None:
            try:
                managed_capture.stop(analyze=True, protect_export=True)
            except Exception as exc:
                print(f"CAPTURE FINALIZATION ERROR: {exc}", file=sys.stderr)
                exit_code = 1
        try:
            write_runtime_status(managed_capture, "stopped" if exit_code == 0 else "failed")
        except OSError as exc:
            print(f"Could not save final runtime status: {exc}", file=sys.stderr)
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
