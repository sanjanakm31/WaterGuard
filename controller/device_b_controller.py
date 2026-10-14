"""
controller/device_b_controller.py

Device B -- the protected water-control controller. Exposes a Modbus TCP
server backed by three holding registers representing the physical state of
a simplified water-treatment stage.

    Register 0  chlorine dosing level, hundredths of a ppm (150 == 1.50 ppm)
    Register 1  valve position, percent open (0-100)
    Register 2  simulated flow-rate sensor, litres/minute -- READ-ONLY; a
                background thread perturbs this value every second to
                emulate a live physical process.

The server uses PyModbus's current SimData/SimDevice model.  The background
process simulator deliberately talks to the server through a normal Modbus
client instead of reaching into PyModbus's private datastore internals.  This
keeps the simulation compatible with the exact PyModbus release pinned in
requirements.txt and exercises the same register path as the dashboard.
"""

from __future__ import annotations

import argparse
import logging
import random
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from shared import config  # noqa: E402  (import after sys.path fixup, see above)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] waterguard.device_b: %(message)s")
logger = logging.getLogger("waterguard.device_b")

REG_CHLORINE = config.REGISTER_CHLORINE_PPM_X100
REG_VALVE = config.REGISTER_VALVE_POSITION_PCT
REG_FLOW = config.REGISTER_FLOW_RATE_LPM


def _build_context():
    from pymodbus.simulator import DataType, SimData, SimDevice

    # Realistic, safe baseline: 1.50 ppm chlorine, 50% valve open, ~120 L/min flow.
    initial_values = [0] * 16
    initial_values[REG_CHLORINE] = 150
    initial_values[REG_VALVE] = 50
    initial_values[REG_FLOW] = 120

    return SimDevice(
        id=1,
        simdata=SimData(
            address=0,
            values=initial_values,
            datatype=DataType.REGISTERS,
        ),
    )


def _checked_registers(result, operation: str) -> list[int]:
    """Return a successful PyModbus read result or raise a useful error."""
    if result.isError():
        raise RuntimeError(f"{operation} returned an error response: {result}")
    return list(result.registers)


def _checked_write(result, operation: str) -> None:
    """Validate a PyModbus write response."""
    if result.isError():
        raise RuntimeError(f"{operation} returned an error response: {result}")


def _process_simulation_tick(client, rng=random) -> None:
    """Apply one flow-drift/chlorine-decay update through Modbus TCP."""
    flow_result = client.read_holding_registers(REG_FLOW, count=1, device_id=1)
    flow = _checked_registers(flow_result, "flow read")[0]
    drifted = max(80, min(160, flow + rng.randint(-3, 3)))
    _checked_write(
        client.write_register(REG_FLOW, drifted, device_id=1),
        "flow update",
    )

    chlorine_result = client.read_holding_registers(REG_CHLORINE, count=1, device_id=1)
    chlorine = _checked_registers(chlorine_result, "chlorine read")[0]
    if rng.random() < 0.3 and chlorine > 0:
        _checked_write(
            client.write_register(REG_CHLORINE, chlorine - 1, device_id=1),
            "chlorine update",
        )


def _process_simulation_loop(host: str, port: int, stop_event: threading.Event) -> None:
    """
    Background thread emulating a live physical process: the flow-rate
    sensor (register 2) drifts slightly every second, and the chlorine
    level (register 0) decays very slowly over time unless corrected by a
    legitimate, authenticated dosing command routed through the Gateway.
    """
    from pymodbus.client import ModbusTcpClient

    client = ModbusTcpClient(host, port=port)
    connected = False
    failure_reported = False
    try:
        while not stop_event.wait(1.0):
            try:
                if not connected:
                    connected = bool(client.connect())
                    if not connected:
                        raise ConnectionError(f"could not connect to local Device B server at {host}:{port}")
                _process_simulation_tick(client)
                failure_reported = False
            except Exception as exc:
                connected = False
                client.close()
                if not failure_reported:
                    logger.warning("process simulation temporarily unavailable: %s", exc)
                    failure_reported = True
    finally:
        client.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="WaterGuard Device B -- protected water-control controller")
    parser.add_argument(
        "--host", default="127.0.0.1",
        help="Bind address. Default: localhost only, for a gateway and controller "
             "on the same computer. A separate controller VM requires an explicit "
             "LAN bind address AND firewall rules allowing only the gateway host.",
    )
    parser.add_argument("--port", type=int, default=config.CONTROLLER_MODBUS_PORT)
    args = parser.parse_args()

    try:
        from pymodbus import ModbusDeviceIdentification
        from pymodbus.server import StartTcpServer
    except ImportError as exc:
        logger.error(
            "pymodbus is not installed. Run: pip install -r requirements.txt "
            "(see README.md's pymodbus version troubleshooting section if this "
            "still fails after installing)."
        )
        raise SystemExit(1) from exc

    server_context = _build_context()

    identity = ModbusDeviceIdentification()
    identity.VendorName = "WaterGuard Capstone Project"
    identity.ProductCode = "WG-CTRL-SIM"
    identity.ProductName = "Simulated Water-Control Controller (Device B)"
    identity.ModelName = "Device B"
    identity.MajorMinorRevision = "1.0.0"

    stop_event = threading.Event()
    simulation_host = "127.0.0.1" if args.host in {"", "0.0.0.0"} else args.host
    sim_thread = threading.Thread(
        target=_process_simulation_loop,
        args=(simulation_host, args.port, stop_event),
        daemon=True,
    )
    sim_thread.start()

    logger.info("Device B (protected controller) starting Modbus TCP server on %s:%d", args.host, args.port)
    logger.warning(
        "SECURITY NOTE: in your multi-VM deployment, this port must accept "
        "inbound connections ONLY from the WaterGuard Gateway's VM IP -- "
        "configure this as a host firewall / security-group rule on Device B's "
        "VM. See README.md 'Multi-VM deployment' section."
    )
    try:
        StartTcpServer(context=server_context, identity=identity, address=(args.host, args.port))
    except KeyboardInterrupt:
        stop_event.set()


if __name__ == "__main__":
    main()
