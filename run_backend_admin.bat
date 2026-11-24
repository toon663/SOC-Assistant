@echo off
rem Starts the SOC backend as Administrator so it can read the Security log.
rem Double-click this file. Windows shows a UAC prompt on each start.

fltmc >nul 2>&1
if errorlevel 1 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0backend"
rem Claude reviews incidents the rules can't settle. Needs ANTHROPIC_API_KEY set as a Windows user variable.
set SOC_LLM_TRIAGE=auto
set "SOC_BACKEND_PYTHON=%~dp0.venv\Scripts\python.exe"
if not exist "%SOC_BACKEND_PYTHON%" set "SOC_BACKEND_PYTHON=python"
echo Dashboard: http://127.0.0.1:8000/app/
"%SOC_BACKEND_PYTHON%" -m uvicorn api:app --host 127.0.0.1 --port 8000
pause
