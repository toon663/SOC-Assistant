@echo off
rem Starts the SOC backend as Administrator so it can read the Security log.
rem Double-click this file. Windows shows a UAC prompt on each start.

fltmc >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0backend"
echo Dashboard: http://127.0.0.1:8000/app/
"%~dp0.venv\Scripts\python.exe" -m uvicorn api:app --host 127.0.0.1 --port 8000
pause
