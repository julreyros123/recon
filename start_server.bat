@echo off
title Knowsec Server
cd /d "c:\Users\acer laptop\Knowsec"

:: Start Tailscale if not already running
tailscale up

:: Activate venv and start FastAPI server
call venv\Scripts\activate
uvicorn app.main:app --host 0.0.0.0 --port 8000
