@echo off
echo Activating virtual environment...
call venv_fresh\Scripts\activate.bat
echo.
echo Checking database...
python check_db.py
echo.
echo Initializing database...
python init_db.py
echo.
echo Database initialization complete!
echo. 