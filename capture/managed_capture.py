"""Managed TShark lifecycle for the one-command WaterGuard launcher.

Capture starts before Device B or the gateway, so every TCP exchange created
by the launcher is eligible for capture. On shutdown the capture is closed,
analyzed through PyShark, and exported as hashed, signed, encrypted evidence.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from capture.pcap_capture import CAPTURE_DIR, build_bpf_filter

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"


@dataclass(frozen=True)
class CaptureArtifacts:
    pcap: Path
    analysis: Path | None = None
    encrypted_export: Path | None = None
    export_manifest: Path | None = None


def find_tshark() -> str:
    """Return a usable TShark executable path or raise an actionable error."""
    discovered = shutil.which("tshark")
    if discovered:
        return discovered

    candidates: list[Path] = []
    for variable in ("ProgramFiles", "ProgramW6432"):
        base = os.environ.get(variable)
        if base:
            candidates.append(Path(base) / "Wireshark" / "tshark.exe")
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)

    raise RuntimeError(
        "TShark was not found. Install Wireshark with TShark and Npcap from "
        "https://www.wireshark.org/download.html, then rerun WaterGuard. "
        "Use --no-capture only when intentionally running without PCAP evidence."
    )


def parse_tshark_interfaces(output: str) -> list[tuple[str, str]]:
    """Parse `tshark -D` output into `(capture_name, description)` pairs."""
    interfaces: list[tuple[str, str]] = []
    for line in output.splitlines():
        match = re.match(r"^\s*\d+\.\s+(.+?)\s*$", line)
        if not match:
            continue
        remainder = match.group(1)
        if " (" in remainder:
            name, description = remainder.split(" (", 1)
            description = description.rstrip(")")
        else:
            name, description = remainder, remainder
        interfaces.append((name.strip(), description.strip()))
    return interfaces


def choose_capture_interface(tshark: str, requested: str = "auto") -> str:
    """Resolve an explicit interface or choose the OS loopback interface."""
    if requested and requested.lower() != "auto":
        return requested

    result = subprocess.run(
        [tshark, "-D"], capture_output=True, text=True, timeout=15, check=False
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"TShark could not list capture interfaces: {detail}")

    interfaces = parse_tshark_interfaces(result.stdout)
    if not interfaces:
        raise RuntimeError("TShark reported no capture interfaces; verify Npcap/dumpcap permissions.")

    if sys.platform.startswith("linux"):
        platform_preferences = ("lo",)
    elif sys.platform == "darwin":
        platform_preferences = ("lo0",)
    else:
        platform_preferences = ("\\Device\\NPF_Loopback",)

    for preferred in platform_preferences:
        for name, _description in interfaces:
            if name.casefold() == preferred.casefold():
                return name

    for name, description in interfaces:
        if "loopback" in f"{name} {description}".casefold():
            return name

    available = ", ".join(name for name, _description in interfaces)
    raise RuntimeError(
        "No loopback capture interface was detected. Run `tshark -D` and pass the correct "
        f"name with --capture-interface. Available interfaces: {available}"
    )


class ManagedCapture:
    """Start, stop, analyze, and protect a launcher-owned TShark capture."""

    def __init__(self, requested_interface: str = "auto") -> None:
        self.requested_interface = requested_interface
        self.tshark = find_tshark()
        requested = [item.strip() for item in requested_interface.split(",") if item.strip()]
        self.interfaces = [choose_capture_interface(self.tshark, item) for item in (requested or ["auto"])]
        self.interface = ",".join(self.interfaces)
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%SZ")
        self.output_path = CAPTURE_DIR / f"waterguard_{stamp}.pcapng"
        self.log_path = LOG_DIR / f"capture_{stamp}.log"
        self._process: subprocess.Popen[bytes] | None = None
        self._log_handle = None
        self._monitor_process: subprocess.Popen[bytes] | None = None
        self._monitor_log_handle = None
        self.monitor_log_path = LOG_DIR / f"live_detector_{stamp}.log"

    def start(self) -> Path:
        if self._process is not None:
            raise RuntimeError("managed capture has already been started")

        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.log_path.open("wb")
        command = [self.tshark]
        for interface in self.interfaces:
            command.extend(["-i", interface])
        command.extend([
            "-f", build_bpf_filter(),
            "-w", str(self.output_path),
            "-q",
        ])
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0
        self._process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.DEVNULL,
            stderr=self._log_handle,
            creationflags=creationflags,
            start_new_session=os.name != "nt",
        )
        time.sleep(0.8)
        if self._process.poll() is not None:
            self._close_log()
            detail = self.log_path.read_text(encoding="utf-8", errors="replace").strip()
            raise RuntimeError(
                f"TShark capture failed on interface {self.interface!r}: "
                f"{detail or 'process exited without diagnostic output'}"
            )
        print(
            f"PCAP capture active on {self.interface!r}: {self.output_path} "
            f"(filter: {build_bpf_filter()})"
        )
        self._monitor_log_handle = self.monitor_log_path.open("wb")
        self._monitor_process = subprocess.Popen(
            [sys.executable, "-m", "capture.live_monitor", "--tshark-path", self.tshark,
             "--interfaces", *self.interfaces],
            cwd=ROOT, stdout=self._monitor_log_handle, stderr=subprocess.STDOUT,
            creationflags=creationflags, start_new_session=os.name != "nt",
        )
        time.sleep(0.8)
        self.ensure_running()
        print("Live PyShark analysis enabled; packet observations appear as ALERT events.")
        return self.output_path

    def ensure_running(self) -> None:
        for process, name, log_path in (
            (self._process, "PCAP recorder", self.log_path),
            (self._monitor_process, "live PyShark detector", self.monitor_log_path),
        ):
            if process is None or process.poll() is not None:
                detail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:] if log_path.exists() else ""
                raise RuntimeError(f"{name} stopped unexpectedly; see {log_path}. {detail}")

    @staticmethod
    def _stop_process(process) -> None:
        if process is None or process.poll() is not None:
            return
        try:
            process.send_signal(signal.CTRL_BREAK_EVENT if os.name == "nt" else signal.SIGINT)
            process.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def stop(self, *, analyze: bool = True, protect_export: bool = True) -> CaptureArtifacts:
        self._stop_process(self._monitor_process)
        process = self._process
        if process is not None and process.poll() is None:
            try:
                if os.name == "nt":
                    process.send_signal(signal.CTRL_BREAK_EVENT)
                else:
                    process.send_signal(signal.SIGINT)
                process.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        self._close_log()

        if not self.output_path.is_file() or self.output_path.stat().st_size == 0:
            raise RuntimeError(f"capture did not produce a readable PCAP file; see {self.log_path}")

        analysis_path: Path | None = None
        encrypted_path: Path | None = None
        manifest_path: Path | None = None
        finalization_errors: list[str] = []
        if analyze:
            try:
                from capture.pcap_analyzer import analyze_pcap

                report = analyze_pcap(self.output_path, tshark_path=self.tshark)
                analysis_path = self.output_path.with_suffix(self.output_path.suffix + ".analysis.json")
                analysis_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
                print(f"PCAP analysis written: {analysis_path}")
            except Exception as exc:
                finalization_errors.append(f"analysis failed: {exc}")

        if protect_export:
            try:
                from tools.export_evidence_pcap import export_file

                encrypted_path, manifest_path = export_file(self.output_path)
                print(f"Encrypted PCAP export written: {encrypted_path}")
                print(f"Signed export manifest written: {manifest_path}")
            except Exception as exc:
                finalization_errors.append(f"protected export failed: {exc}")

        if finalization_errors:
            raise RuntimeError("; ".join(finalization_errors))

        return CaptureArtifacts(
            pcap=self.output_path,
            analysis=analysis_path,
            encrypted_export=encrypted_path,
            export_manifest=manifest_path,
        )

    def _close_log(self) -> None:
        if self._log_handle is not None:
            self._log_handle.close()
            self._log_handle = None
        if self._monitor_log_handle is not None:
            self._monitor_log_handle.close()
            self._monitor_log_handle = None
