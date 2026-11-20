@echo off
rem Starts the SOC backend as Administrator in DEV MODE (test scenarios, malware demo, resets).
rem For testing and demos only. Use run_backend_admin.bat for normal use.

fltmc >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0backend"
set SOC_DEV_MODE=1
echo DEV MODE - Dashboard: http://127.0.0.1:8000/app/
"%~dp0.venv\Scripts\python.exe" -m uvicorn api:app --host 127.0.0.1 --port 8000
pause
