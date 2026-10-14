from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from tools.generate_tls_cert import CERT_PATH, KEY_PATH, generate

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port: int, process: subprocess.Popen, timeout: float = 15.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"dashboard exited during startup with code {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"dashboard did not open HTTPS port {port}")


def test_https_dashboard_boots_and_serves_apis():
    if not CERT_PATH.exists() or not KEY_PATH.exists():
        generate(valid_days=30)
    port = free_port()
    process = subprocess.Popen(
        [sys.executable, "-m", "dashboard.app", "--test-mode", "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT,
    )
    try:
        wait_port(port, process)
        tls_context = ssl._create_unverified_context()
        with urllib.request.urlopen(f"https://127.0.0.1:{port}/api/state", context=tls_context, timeout=5) as response:
            state = json.load(response)
        with urllib.request.urlopen(f"https://127.0.0.1:{port}/api/events", context=tls_context, timeout=5) as response:
            events = json.load(response)
        assert response.status == 200
        assert len(state["registers"]) == 3
        assert isinstance(events["events"], list)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
