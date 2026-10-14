"""
dashboard/app.py

Live WaterGuard dashboard: a FastAPI application serving two small JSON
APIs (live process state, recent security events) and a single
self-contained HTML/JS page that polls both and renders them in real time.
Served over HTTPS/TLS with a self-signed certificate, per the synopsis's
explicit "dashboard, served over HTTPS/TLS" requirement.

WHY READS BYPASS THE GATEWAY'S WRITE-AUTHENTICATION PIPELINE
---------------------------------------------------------------
See controller/modbus_forwarder.py's module docstring: a read cannot change
the physical process, so it is treated as a separate, lower-trust telemetry
channel rather than routed through WCP. Firewall Device B's Modbus port to
accept the dashboard's VM IP for reads, in addition to the Gateway's VM IP
for writes, in your multi-VM deployment.

RUNNING
-------
    python3 -m tools.generate_tls_cert        # once, if tls/ doesn't exist yet
    python3 -m dashboard.app --test-mode      # static demo state, no Device B needed
    python3 -m dashboard.app                  # real Device B state (production)

Then open https://localhost:8443/ and accept the self-signed-certificate
browser warning (expected — see tools/generate_tls_cert.py).

The dashboard verifies each encrypted evidence row before displaying it.
Rows that fail verification are labeled TAMPERED and their untrusted
cleartext metadata is not rendered as an authentic event.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi import FastAPI, Request  # noqa: E402
from fastapi.responses import HTMLResponse, JSONResponse  # noqa: E402

from controller.modbus_forwarder import LoopbackTestForwarder, ModbusForwarder, RealModbusForwarder  # noqa: E402
from gateway import evidence_store  # noqa: E402
from shared import config  # noqa: E402

from fastapi.staticfiles import StaticFiles
from dashboard.presentation_api import router

app = FastAPI(title="WaterGuard Live Dashboard", docs_url=None, redoc_url=None)
app.include_router(router)
app.mount("/assets", StaticFiles(directory=Path(__file__).resolve().parent.parent / "ui"), name="assets")

@app.middleware("http")
async def browser_headers(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    return response
evidence_store.init_db()

_forwarder: Optional[ModbusForwarder] = None  # configured in main() before uvicorn.run()

REGISTER_LABELS = {
    config.REGISTER_CHLORINE_PPM_X100: {"name": "Chlorine dosing", "unit": "ppm", "scale": 0.01},
    config.REGISTER_VALVE_POSITION_PCT: {"name": "Valve position", "unit": "%", "scale": 1.0},
    config.REGISTER_FLOW_RATE_LPM: {"name": "Flow rate (sensor)", "unit": "L/min", "scale": 1.0},
}


def configure_forwarder(forwarder: ModbusForwarder) -> None:
    global _forwarder
    _forwarder = forwarder


@app.get("/api/state")
def get_state() -> JSONResponse:
    if _forwarder is None:
        return JSONResponse(status_code=503, content={"error": "controller connection not configured"})
    try:
        raw_values = _forwarder.read_registers(0, 3)
    except Exception as exc:
        return JSONResponse(status_code=502, content={"error": f"could not read controller state: {exc!r}"})

    registers = []
    for addr, raw in enumerate(raw_values):
        meta = REGISTER_LABELS.get(addr, {"name": f"register {addr}", "unit": "", "scale": 1.0})
        low_high = config.SAFETY_BOUNDS.get(addr)
        display_value = round(raw * meta["scale"], 2)
        in_bounds = True
        if low_high is not None:
            low, high = low_high
            in_bounds = low <= raw <= high
        registers.append({
            "address": addr,
            "name": meta["name"],
            "raw_value": raw,
            "display_value": display_value,
            "unit": meta["unit"],
            "writable": addr in config.WRITABLE_REGISTERS,
            "safe_bound_raw": low_high,
            "in_bounds": in_bounds,
        })
    return JSONResponse(content={"registers": registers})


@app.get("/api/events")
def get_events(request: Request, limit: int = 50) -> JSONResponse:
    limit = max(1, min(limit, 500))
    events = evidence_store.fetch_recent_events(limit=limit)
    from shared.ui_security import require_local
    from fastapi import HTTPException
    try:
        require_local(request)
        local = True
    except HTTPException:
        local = False
    if not local:
        for event in events:
            event['extra'].pop('command', None)
            event['extra'].pop('raw_preview', None)
    return JSONResponse(content={"events": events})


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (Path(__file__).resolve().parent.parent / "ui" / "dashboard.html").read_text(encoding="utf-8")




def main() -> None:
    import uvicorn

    parser = argparse.ArgumentParser(description="WaterGuard live dashboard")
    parser.add_argument("--host", default=config.DASHBOARD_HOST)
    parser.add_argument("--port", type=int, default=config.DASHBOARD_PORT)
    parser.add_argument("--controller-host", default=config.CONTROLLER_HOST)
    parser.add_argument("--controller-port", type=int, default=config.CONTROLLER_MODBUS_PORT)
    parser.add_argument(
        "--test-mode", action="store_true",
        help="Use an in-memory LoopbackTestForwarder with static demo state instead of a real Device B.",
    )
    args = parser.parse_args()

    if args.test_mode:
        configure_forwarder(LoopbackTestForwarder())
    else:
        configure_forwarder(RealModbusForwarder(args.controller_host, args.controller_port))

    cert_path = Path(__file__).resolve().parent.parent / "tls" / "dashboard_cert.pem"
    key_path = Path(__file__).resolve().parent.parent / "tls" / "dashboard_key.pem"
    if not cert_path.exists() or not key_path.exists():
        raise SystemExit("TLS certificate not found. Run: python3 -m tools.generate_tls_cert")

    uvicorn.run(app, host=args.host, port=args.port, ssl_certfile=str(cert_path), ssl_keyfile=str(key_path))


if __name__ == "__main__":
    main()
