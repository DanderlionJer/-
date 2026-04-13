@echo off
chcp 65001 >nul
title CryptoToolbox
echo ================================
echo   CryptoToolbox - Starting...
echo ================================
echo.

cd /d "%~dp0"

:: Check if dependencies are installed
pip show flask >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing dependencies...
    pip install -r requirements.txt
    echo.
)

echo Starting server at http://localhost:5000
echo Press Ctrl+C to stop
echo.

:: Open browser after 1 second delay
start "" cmd /c "timeout /t 1 /nobreak >nul && start http://localhost:5000"

:: Start Flask
python app.py
