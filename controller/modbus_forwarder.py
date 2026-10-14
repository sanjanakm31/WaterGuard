"""
controller/modbus_forwarder.py

Defines the interface the WaterGuard Gateway (writes) and the dashboard
(reads) use to talk to Device B, plus two implementations:

    RealModbusForwarder    -- production implementation. Opens a real
                              pymodbus TCP client connection to Device B for
                              both reads and writes. THIS is what must be
                              used for your graded multi-VM demo, your
                              benchmarking numbers, and the dashboard.

    LoopbackTestForwarder  -- an in-memory stand-in used by
                              run_local_pipeline_demo.py and
                              benchmarking/benchmark_gateway.py to exercise
                              the Gateway's validation pipeline and timing
                              instrumentation on a machine without pymodbus
                              installed. It maintains its own in-memory
                              register state (seeded to match Device B's
                              real startup defaults) so reads reflect prior
                              writes exactly as a real controller would.

Read access is intentionally NOT routed through the Gateway's WCP
authentication pipeline: a read cannot change the physical process, so
authenticating it adds latency and complexity without a corresponding
safety benefit. Document this explicitly as a deliberate scope decision in
the report if asked at viva -- the write path is fully authenticated and
enforced; the read (telemetry) path is a separate, lower-trust channel, the
same way many real SCADA deployments separate a read-only historian feed
from the control path. The multi-VM firewall rule on Device B's port must
therefore allow the dashboard's VM IP to connect for reads, in addition to
the Gateway's VM IP for writes -- see README.md.

pymodbus is imported lazily inside RealModbusForwarder.__init__ (not at
module load time) so that code paths using only LoopbackTestForwarder can
run on a machine where pymodbus has not been installed.
"""

from __future__ import annotations

import logging

from shared import config

logger = logging.getLogger("waterguard.modbus_forwarder")


class ModbusForwarder:
    def write_register(self, register: int, value: int) -> None:
        """
        Writes `value` to holding register `register` on the protected
        controller. Must raise an exception on any failure -- the Gateway
        treats a raised exception here as "controller_unreachable" and
        blocks the request rather than silently dropping it.
        """
        raise RuntimeError("ModbusForwarder.write_register must be implemented by a concrete forwarder")

    def read_registers(self, start: int, count: int) -> list[int]:
        """Reads `count` holding registers starting at `start`. Raises on failure."""
        raise RuntimeError("ModbusForwarder.read_registers must be implemented by a concrete forwarder")


class RealModbusForwarder(ModbusForwarder):
    """Production forwarder -- issues real Modbus TCP reads/writes via pymodbus."""

    def __init__(self, host: str, port: int):
        try:
            from pymodbus.client import ModbusTcpClient  # noqa: PLC0415 (intentional lazy import)
        except ImportError as exc:
            raise ImportError(
                "pymodbus is required for RealModbusForwarder. Install project "
                "dependencies first: pip install -r requirements.txt"
            ) from exc
        self._client_cls = ModbusTcpClient
        self._host = host
        self._port = port

    def write_register(self, register: int, value: int) -> None:
        client = self._client_cls(self._host, port=self._port)
        try:
            if not client.connect():
                raise ConnectionError(
                    f"could not connect to protected controller (Device B) at {self._host}:{self._port}"
                )
            result = client.write_register(register, value, device_id=1)
            if result.isError():
                raise RuntimeError(f"Modbus write_register returned an error response: {result}")
        finally:
            client.close()

    def read_registers(self, start: int, count: int) -> list[int]:
        client = self._client_cls(self._host, port=self._port)
        try:
            if not client.connect():
                raise ConnectionError(
                    f"could not connect to protected controller (Device B) at {self._host}:{self._port}"
                )
            result = client.read_holding_registers(start, count=count, device_id=1)
            if result.isError():
                raise RuntimeError(f"Modbus read_holding_registers returned an error response: {result}")
            return list(result.registers)
        finally:
            client.close()


class LoopbackTestForwarder(ModbusForwarder):
    """
    In-memory stand-in for local pipeline testing and benchmarking ONLY.
    Never use this for the graded demo, screenshots, or reported
    benchmark numbers -- those must come from a real Device B via
    RealModbusForwarder, since LoopbackTestForwarder has zero network/OS
    overhead and would make the Gateway look artificially faster than it
    is in a real deployment.
    """

    def __init__(self):
        self.written: list[tuple[int, int]] = []
        # Seed with the exact same defaults as controller/device_b_controller.py
        # so a local demo's read-back behavior matches the real controller.
        self._registers: dict[int, int] = {
            config.REGISTER_CHLORINE_PPM_X100: 150,
            config.REGISTER_VALVE_POSITION_PCT: 50,
            config.REGISTER_FLOW_RATE_LPM: 120,
        }
        logger.warning(
            "LoopbackTestForwarder is ACTIVE -- reads/writes are served from in-memory "
            "state only and are NOT sent to a real Modbus controller."
        )

    def write_register(self, register: int, value: int) -> None:
        self.written.append((register, value))
        self._registers[register] = value
        logger.info("[LoopbackTestForwarder] recorded write register=%d value=%d", register, value)

    def read_registers(self, start: int, count: int) -> list[int]:
        return [self._registers.get(addr, 0) for addr in range(start, start + count)]
