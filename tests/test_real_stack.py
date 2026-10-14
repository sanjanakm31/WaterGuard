from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

from attacker.device_a_attacker import attack_unauthenticated_modbus
from client.legit_hmi_client import send_command
from controller.modbus_forwarder import RealModbusForwarder
from gateway import evidence_store
from gateway.waterguard_gateway import WaterGuardGateway

ROOT = Path(__file__).resolve().parent.parent


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port: int, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"port {port} did not open")


def test_real_pymodbus_controller_gateway_path(tmp_path, monkeypatch):
    ports: set[int] = set()
    while len(ports) < 3:
        ports.add(free_port())
    controller_port, gateway_port, gateway_modbus_port = ports
    monkeypatch.setattr(evidence_store, "DB_PATH", tmp_path / "real-stack.db")
    controller_started = time.monotonic()
    controller = subprocess.Popen(
        [sys.executable, "-m", "controller.device_b_controller", "--host", "127.0.0.1", "--port", str(controller_port)],
        cwd=ROOT,
    )
    gateway = None
    try:
        wait_port(controller_port)
        forwarder = RealModbusForwarder("127.0.0.1", controller_port)
        initial = forwarder.read_registers(0, 3)
        # A slow Windows startup may already have completed simulation ticks.
        # Each tick can reduce chlorine by at most one raw unit per second.
        minimum_initial = max(0, 150 - int(time.monotonic() - controller_started) - 1)
        assert minimum_initial <= initial[0] <= 150
        assert initial[1] == 50
        # Regression: the process simulation must complete a tick without the
        # removed ModbusDeviceContext.getValues/setValues API.  Flow can remain
        # numerically equal when random drift is zero, so verify that the
        # controller remains healthy after multiple scheduled ticks.
        time.sleep(2.2)
        simulated = forwarder.read_registers(0, 3)
        assert 0 <= simulated[0] <= 150
        assert 80 <= simulated[2] <= 160
        gateway = WaterGuardGateway(
            forwarder,
            host="127.0.0.1",
            port=gateway_port,
            modbus_intake_port=gateway_modbus_port,
        )
        gateway.start(blocking=False)
        result = send_command("hmi-01", 1, 65, gateway_host="127.0.0.1", gateway_port=gateway_port)
        assert result["decision"] == "ALLOW"
        assert forwarder.read_registers(1, 1) == [65]
        raw_attack = attack_unauthenticated_modbus("127.0.0.1", gateway_modbus_port)
        assert raw_attack["decision"] == "BLOCK"
        # The live process simulator may legitimately decay chlorine from its
        # initial value while this test runs.  What matters here is that the
        # blocked raw attack never writes its malicious value (2500).
        assert forwarder.read_registers(0, 1) != [2500]
    finally:
        if gateway is not None:
            gateway.stop()
        controller.terminate()
        try:
            controller.wait(timeout=5)
        except subprocess.TimeoutExpired:
            controller.kill()
