@echo off
setlocal
cd /d "%~dp0"
title WaterGuard Ubuntu Client Export
set "WG_ROLE=protected-host"
echo Creating Device_A_Only.zip in this project folder...
if exist ".venv\Scripts\python.exe" (
  ".venv\Scripts\python.exe" -m tools.export_device_a_bundle
) else if exist "%USERPROFILE%\Downloads\WaterGuard_Updated_v2_Windows_Fixed\waterguard\.venv\Scripts\python.exe" (
  "%USERPROFILE%\Downloads\WaterGuard_Updated_v2_Windows_Fixed\waterguard\.venv\Scripts\python.exe" -m tools.export_device_a_bundle
) else (
  py -3.12 -m tools.export_device_a_bundle
)
if errorlevel 1 (
  echo.
  echo Export failed. Keep this window open and share the error shown above.
  pause
  exit /b 1
)
echo.
echo Ubuntu package ready: Device_A_Only.zip
echo The project folder will now open. Copy that ZIP to Ubuntu.
start "" explorer.exe "."
pause
