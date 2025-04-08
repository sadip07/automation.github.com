@echo off
echo Activating virtual environment...
call venv_fresh\Scripts\activate.bat
echo.
echo Starting the application...
python app.py
echo. 