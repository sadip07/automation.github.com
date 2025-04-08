@echo off
echo Creating a new virtual environment...
python -m venv venv_fresh
echo.
echo Activating virtual environment...
call venv_fresh\Scripts\activate.bat
echo.
echo Installing required packages...
python -m pip install --upgrade pip
pip install flask==3.0.0 flask-cors==4.0.0 flask-sqlalchemy==3.1.1 flask-login==0.6.3 flask-bcrypt==1.0.1
pip install python-dotenv==1.0.0 openai==1.3.0 google-generativeai==0.3.2 anthropic==0.7.0
pip install huggingface-hub==0.19.4 tweepy==4.14.0 python-wordpress-xmlrpc==2.3 facebook-sdk==3.1.0
pip install apscheduler==3.10.4 requests==2.31.0 html2text==2020.1.16 gunicorn==21.2.0 python-jose==3.3.0
pip install Werkzeug==3.0.1 itsdangerous==2.1.2 Jinja2==3.1.3 SQLAlchemy==2.0.23 MarkupSafe==2.1.3 cryptography==41.0.5
echo.
echo Setup complete! Use "venv_fresh\Scripts\activate.bat" to activate the environment in the future.
echo. 