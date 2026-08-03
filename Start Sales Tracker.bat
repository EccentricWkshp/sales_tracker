@echo off
setlocal

:: Run from this script's own folder, whatever directory it was launched from
cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo Could not find venv\Scripts\python.exe
    echo Create the virtual environment first:
    echo     python -m venv venv
    echo     venv\Scripts\python -m pip install -r requirements.txt
    pause
    exit /b 1
)

:: app.py serves with waitress on 0.0.0.0:4444 so the app is reachable on the LAN.
:: Both launch paths now agree on the port; override with SALES_TRACKER_PORT.
"venv\Scripts\python.exe" app.py

:: Keep the window open if the server exits so the error stays readable
echo.
echo Sales Tracker has stopped.
pause
