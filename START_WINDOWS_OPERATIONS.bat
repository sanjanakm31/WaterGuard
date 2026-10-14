@echo off
setlocal
cd /d "%~dp0"
title WaterGuard Application
set "WG_ROLE=protected-host"
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m tools.launch_windows
) else (
  py -3.12 tools\bootstrap_windows.py
)
if errorlevel 1 (
  echo.
  echo Startup did not finish. Read the message above.
  echo Python 3.12 and Wireshark with Npcap are needed on Windows.
  pause
)
