@echo off
cd /d "%~dp0"
venv\Scripts\uvicorn.exe app.main:app --host 0.0.0.0 --port 8000 > uvicorn.log 2>&1
