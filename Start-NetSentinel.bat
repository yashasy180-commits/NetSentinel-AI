@echo off
title NetSentinel AI Launcher

echo ==========================================
echo       NetSentinel AI Starting...
echo ==========================================
echo.

echo Starting Backend...
start "NetSentinel Backend" cmd /k "cd /d C:\NetSentinel-AI\backend && C:\NetSentinel-AI\.venv\Scripts\python.exe app.py"

timeout /t 5 /nobreak >nul

echo Starting Frontend...
start "NetSentinel Frontend" cmd /k "cd /d C:\NetSentinel-AI\frontend && npm run dev"

timeout /t 7 /nobreak >nul

echo Opening NetSentinel AI...
start "" "http://localhost:5173"

echo.
echo NetSentinel AI is starting...
