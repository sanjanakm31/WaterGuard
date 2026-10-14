@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
  echo WaterGuard has not been set up yet.
  echo Run setup_windows.bat first.
  pause
  exit /b 1
)
echo Starting WaterGuard. Keep this window open.
echo The dashboard will be at https://localhost:8443/
echo.
".venv\Scripts\python.exe" run_waterguard.py
if errorlevel 1 (
  echo.
  echo WaterGuard stopped because of an error. Review the message above.
  pause
)
