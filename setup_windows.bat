@echo off
setlocal
cd /d "%~dp0"
call setup_only_windows.bat
if errorlevel 1 (
  echo.
  echo Setup stopped. Read the error above and START_HERE.txt.
  pause
  exit /b 1
)
call start_windows.bat
