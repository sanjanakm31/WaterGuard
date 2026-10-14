#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
export WG_ROLE=device-a
if [[ -x .venv/bin/python ]] && .venv/bin/python -c 'import fastapi,uvicorn,cryptography,pymodbus' >/dev/null 2>&1; then
  WG_CLIENT_PY="$PWD/.venv/bin/python"
elif [[ -x "$HOME/WaterGuardVM/waterguard/.venv/bin/python" ]] && "$HOME/WaterGuardVM/waterguard/.venv/bin/python" -c 'import fastapi,uvicorn,cryptography,pymodbus' >/dev/null 2>&1; then
  WG_CLIENT_PY="$HOME/WaterGuardVM/waterguard/.venv/bin/python"
else
  python3 -m venv .venv
  WG_CLIENT_PY="$PWD/.venv/bin/python"
  "$WG_CLIENT_PY" -m pip install -r requirements_device_a.txt
fi
"$WG_CLIENT_PY" - <<'PY'
import socket
try:
    with socket.create_connection(('127.0.0.1',8080),timeout=.3):
        raise SystemExit('Port 8080 is already in use. Stop your previous Device A launcher before opening this one.')
except OSError:
    pass
PY
"$WG_CLIENT_PY" -m device_a.shortcut
"$WG_CLIENT_PY" -m device_a.app &
WG_CLIENT_PID=$!
cleanup() { kill -TERM "$WG_CLIENT_PID" 2>/dev/null || true; wait "$WG_CLIENT_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
"$WG_CLIENT_PY" - <<'PY'
import time,urllib.request,webbrowser
for _ in range(50):
    try:
        urllib.request.urlopen('http://127.0.0.1:8080/',timeout=.3).close()
        webbrowser.open('http://127.0.0.1:8080/')
        print('DEVICE A READY. If no browser opened, open http://127.0.0.1:8080/ in Ubuntu Firefox.')
        break
    except OSError:
        time.sleep(.2)
else:
    raise SystemExit('Device A did not become ready. Read its error above. Port 8080 may already be in use.')
PY
wait "$WG_CLIENT_PID"
