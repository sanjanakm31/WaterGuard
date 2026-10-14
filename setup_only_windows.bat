@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
  echo Python launcher not found. Install Python 3.12 as explained in START_HERE.txt.
  exit /b 1
)
py -3.12 -m venv .venv || exit /b 1
call .venv\Scripts\activate.bat || exit /b 1
python -m pip install --upgrade pip || exit /b 1
python -m pip install -r requirements.txt || exit /b 1
python -c "from run_waterguard import ensure_configuration; ensure_configuration()" || exit /b 1
python -m tools.check_environment --capture-test || exit /b 1
python -m pytest -q || exit /b 1
echo.
echo Setup and tests passed. Run start_windows.bat when ready to start the demonstration.
exit /b 0
