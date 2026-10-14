"""
shared/config.py

Central configuration for every WaterGuard component (Device B, the Gateway,
the legitimate HMI client, and the Device A attacker suite all import this
module, so there is exactly one source of truth for ports, secrets, the
register map, and safety bounds).

SECURITY NOTE ON SECRETS
------------------------
No secret key is ever hardcoded in this file or anywhere else in the
codebase. All three keys below (COMMAND_HMAC_KEY, EVIDENCE_HMAC_KEY,
EVIDENCE_AES_KEY) are loaded from environment variables that you provision
via a local, untracked `.env` file (see `.env.example` and
`tools/generate_secrets.py`). This mirrors real OT/ICS security-gateway
practice, where a pre-shared key is provisioned out-of-band and never
committed to source control.
"""

from __future__ import annotations

import os
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv(path: Path) -> None:
    """
    Minimal, dependency-free .env loader (deliberately not using
    python-dotenv so the project's only third-party dependencies are the
    ones listed in requirements.txt / the synopsis's software requirements).
    Existing environment variables always take precedence over the .env
    file, matching standard dotenv semantics.
    """
    if not path.exists():
        return
    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            os.environ.setdefault(key, value)


_load_dotenv(_REPO_ROOT / ".env")


def _require_hex_key(env_name: str, byte_length: int) -> bytes:
    value = os.environ.get(env_name)
    if not value:
        raise RuntimeError(
            f"Missing required secret '{env_name}'.\n"
            f"Generate one with:\n"
            f"    python3 tools/generate_secrets.py\n"
            f"and copy the printed value into your .env file "
            f"(see .env.example for the expected format)."
        )
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise RuntimeError(
            f"Environment variable '{env_name}' must be a hex-encoded string."
        ) from exc
    if len(raw) != byte_length:
        raise RuntimeError(
            f"Environment variable '{env_name}' must decode to exactly "
            f"{byte_length} bytes; got {len(raw)} bytes instead."
        )
    return raw


# ---------------------------------------------------------------------------
# Network endpoints
# ---------------------------------------------------------------------------

# Device B (protected controller) — native Modbus TCP, reachable ONLY from
# the Gateway's VM in a real multi-VM deployment (enforce via host firewall
# / security group rule when Device B is on a separate machine). Device B
# does not authenticate Modbus itself. Its default bind is localhost only.
CONTROLLER_HOST = os.environ.get("WG_CONTROLLER_HOST", "127.0.0.1")
CONTROLLER_MODBUS_PORT = int(os.environ.get("WG_CONTROLLER_MODBUS_PORT", "5502"))
# Source IP Device B should observe for gateway-originated Modbus traffic.
# Used by PCAP analysis to flag direct-to-controller bypass attempts.
GATEWAY_TRUSTED_IP = os.environ.get("WG_GATEWAY_TRUSTED_IP", "127.0.0.1")

# WaterGuard Gateway — WaterGuard Command Protocol (WCP) listener. This is
# the ONLY interface untrusted clients (legitimate HMI or attacker) ever
# talk to directly.
GATEWAY_HOST = os.environ.get("WG_GATEWAY_HOST", "0.0.0.0")
GATEWAY_WCP_PORT = int(os.environ.get("WG_GATEWAY_WCP_PORT", "6000"))
# Untrusted-side native Modbus listener. Raw Modbus cannot carry the HMAC
# envelope, so this port records and rejects every request without forwarding.
GATEWAY_MODBUS_PORT = int(os.environ.get("WG_GATEWAY_MODBUS_PORT", "1502"))

# Live dashboard (FastAPI, HTTPS/TLS).
DASHBOARD_HOST = os.environ.get("WG_DASHBOARD_HOST", "0.0.0.0")
DASHBOARD_PORT = int(os.environ.get("WG_DASHBOARD_PORT", "8443"))

# TShark interface used by the managed launcher capture. "auto" resolves to
# the OS loopback interface because the default all-in-one demo uses localhost.
CAPTURE_INTERFACE = os.environ.get("WG_CAPTURE_INTERFACE", "auto")

# ---------------------------------------------------------------------------
# Secrets (provisioned via .env — see tools/generate_secrets.py)
# ---------------------------------------------------------------------------

COMMAND_HMAC_KEY = _require_hex_key("WG_COMMAND_HMAC_KEY", 32)   # WCP command authentication
DEVICE_A_ONLY = os.environ.get("WG_ROLE") == "device-a"
# Device A has no evidence-store capability and needs only the command key.
# None is deliberate: there is no substitute key that could be mistaken for
# the protected host's key. The Device A ZIP excludes the evidence modules.
EVIDENCE_HMAC_KEY = None if DEVICE_A_ONLY else _require_hex_key("WG_EVIDENCE_HMAC_KEY", 32)
EVIDENCE_AES_KEY = None if DEVICE_A_ONLY else _require_hex_key("WG_EVIDENCE_AES_KEY", 32)

# ---------------------------------------------------------------------------
# Authorized source registry: client_id -> the single IP address that
# client_id is permitted to connect from. In the sandbox / single-host demo
# this is a loopback address; in the graded multi-VM deployment these become
# the real VM IPs of your HMI/engineering-workstation VM(s).
# ---------------------------------------------------------------------------


def _load_authorized_sources() -> dict[str, str]:
    raw = os.environ.get("WG_AUTHORIZED_SOURCES", "hmi-01=127.0.0.1")
    sources: dict[str, str] = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry or "=" not in entry:
            continue
        client_id, ip = entry.split("=", 1)
        sources[client_id.strip()] = ip.strip()
    return sources


AUTHORIZED_SOURCES = _load_authorized_sources()

# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------

REPLAY_WINDOW_SECONDS = float(os.environ.get("WG_REPLAY_WINDOW_SECONDS", "5.0"))
NONCE_CACHE_TTL_SECONDS = float(os.environ.get("WG_NONCE_CACHE_TTL_SECONDS", "120.0"))

# ---------------------------------------------------------------------------
# Register map (Device B holding registers)
# ---------------------------------------------------------------------------

REGISTER_CHLORINE_PPM_X100 = 0   # chlorine dosing level, hundredths of a ppm
REGISTER_VALVE_POSITION_PCT = 1  # valve position, percent open (0-100)
REGISTER_FLOW_RATE_LPM = 2       # simulated flow sensor — READ-ONLY

WRITABLE_REGISTERS = {REGISTER_CHLORINE_PPM_X100, REGISTER_VALVE_POSITION_PCT}
READ_ONLY_REGISTERS = {REGISTER_FLOW_RATE_LPM}

# Safe operating bounds, enforced by the Gateway independently of (i.e. even
# after) HMAC authentication succeeds. This is a deliberate defense-in-depth
# layer: a validly authenticated but malicious/compromised client still
# cannot push the physical process into an unsafe state.
#
#   Chlorine: 0.20-4.00 ppm is this prototype's configured policy, not a
#   certification of drinking-water safety. Values are stored x100 (Modbus holding
#   registers are 16-bit unsigned integers, so we avoid floats on the wire).
#
#   Valve: 10-90% is a configurable *operational policy* window (not the
#   device's physical 0-100% range) chosen to avoid instructing a full
#   open/close shock to the process; document this distinction explicitly
#   in the report as a policy choice, not a hardware limit.
SAFETY_BOUNDS: dict[int, tuple[int, int]] = {
    REGISTER_CHLORINE_PPM_X100: (20, 400),
    REGISTER_VALVE_POSITION_PCT: (10, 90),
}

# ---------------------------------------------------------------------------
# Protocol limits
# ---------------------------------------------------------------------------

MAX_WCP_MESSAGE_BYTES = 4096
