@echo off

:: Change directory to sales_tracker
cd /d ".\sales_tracker"

:: Activate the virtual environment
call "venv\Scripts\activate"

:: Run Flask with host 0.0.0.0
flask run -h 0.0.0.0

:: Pause the batch file so it remains open
pause
