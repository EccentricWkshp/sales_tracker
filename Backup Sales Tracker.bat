@echo off
setlocal

:: Standalone database backup, for Windows Task Scheduler.
:: The app also snapshots on every start; this covers boxes that stay up for weeks.
:: Snapshots land in instance\backups\sales-YYYYMMDD-HHMMSS.db (newest 14 kept).

cd /d "%~dp0"

if not exist "venv\Scripts\python.exe" (
    echo Could not find venv\Scripts\python.exe
    exit /b 1
)

"venv\Scripts\python.exe" migrations\backup_db.py
