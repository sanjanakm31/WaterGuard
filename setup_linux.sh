#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
command -v python3 >/dev/null || { echo "Python 3 is required."; exit 1; }
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -c "from run_waterguard import ensure_configuration; ensure_configuration()"
python -m tools.check_environment --capture-test
python -m pytest -q
echo "Setup and tests completed successfully. Starting WaterGuard"
python run_waterguard.py
