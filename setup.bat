@echo off
REM Secure Chat with Dropbox Integration - Windows Setup Script
REM This script helps you set up the application on Windows

setlocal EnableDelayedExpansion

echo ================================
echo Secure Chat - Windows Setup
echo ================================
echo.

REM Check if Python is installed
echo [1/6] Checking Python installation...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found. Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [OK] Python %PYTHON_VERSION% found
echo.

REM Create virtual environment
echo [2/6] Creating virtual environment...
if exist venv (
    echo [WARNING] Virtual environment already exists
) else (
    python -m venv venv
    echo [OK] Virtual environment created
)
echo.

REM Activate virtual environment and install dependencies
echo [3/6] Installing dependencies...
call venv\Scripts\activate.bat
python -m pip install --upgrade pip
pip install -r requirements.txt
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo [OK] All dependencies installed
echo.

REM Database setup
echo [4/6] Database setup...
set /p SETUP_DB="Do you want to set up the database now? (y/n): "
if /i "%SETUP_DB%"=="y" (
    echo.
    echo Please make sure MySQL is running and accessible.
    echo.
    set /p DB_HOST="MySQL host [localhost]: "
    if "!DB_HOST!"=="" set DB_HOST=localhost
    
    set /p DB_USER="MySQL user [root]: "
    if "!DB_USER!"=="" set DB_USER=root
    
    set /p DB_PASSWORD="MySQL password: "
    
    echo.
    echo Creating database...
    mysql -h !DB_HOST! -u !DB_USER! -p!DB_PASSWORD! < setup_db.sql
    if %errorlevel% equ 0 (
        echo [OK] Database created successfully
    ) else (
        echo [WARNING] Could not create database automatically.
        echo Please create it manually using the SQL in setup instructions.
    )
) else (
    echo [WARNING] Skipping database setup.
)
echo.

REM Dropbox setup
echo [5/6] Dropbox setup...
set /p SETUP_DROPBOX="Do you want to configure Dropbox now? (y/n): "
if /i "%SETUP_DROPBOX%"=="y" (
    echo.
    echo To set up Dropbox integration:
    echo 1. Go to https://www.dropbox.com/developers/apps
    echo 2. Click 'Create app'
    echo 3. Choose 'Scoped access' and 'Full Dropbox'
    echo 4. Get your App Key and App Secret
    echo.
    set /p DROPBOX_KEY="Enter your Dropbox App Key: "
    set /p DROPBOX_SECRET="Enter your Dropbox App Secret: "
    
    REM Update dropbox_manager.py
    powershell -Command "(gc dropbox_manager.py) -replace 'YOUR_APP_KEY_HERE', '!DROPBOX_KEY!' | Out-File -encoding ASCII dropbox_manager.py"
    powershell -Command "(gc dropbox_manager.py) -replace 'YOUR_APP_SECRET_HERE', '!DROPBOX_SECRET!' | Out-File -encoding ASCII dropbox_manager.py"
    
    echo [OK] Dropbox credentials updated
) else (
    echo [WARNING] Skipping Dropbox setup.
)
echo.

REM Create startup scripts
echo [6/6] Creating startup scripts...

REM Server startup script
echo @echo off > start_server.bat
echo cd /d "%%~dp0" >> start_server.bat
echo call venv\Scripts\activate.bat >> start_server.bat
echo python server.py >> start_server.bat
echo pause >> start_server.bat
echo [OK] Created start_server.bat

REM Client startup script
echo @echo off > start_client.bat
echo cd /d "%%~dp0" >> start_client.bat
echo call venv\Scripts\activate.bat >> start_client.bat
echo python gui.py >> start_client.bat
echo pause >> start_client.bat
echo [OK] Created start_client.bat
echo.

REM Create config directory
if not exist "%USERPROFILE%\.chat_config" (
    mkdir "%USERPROFILE%\.chat_config"
    echo [OK] Created config directory
)

REM Final instructions
echo.
echo ================================
echo Setup Complete!
echo ================================
echo.
echo [OK] Installation completed successfully!
echo.
echo Next steps:
echo 1. Start the server: start_server.bat
echo 2. Start the client: start_client.bat (in another window)
echo 3. Create an account and start chatting!
echo.
echo For Dropbox integration:
echo 1. Go to the 'Files' tab in the client
echo 2. Click 'Connect Dropbox'
echo 3. Follow the OAuth flow
echo.
echo Documentation:
echo - Quick start: QUICK_START.md
echo - Dropbox setup: DROPBOX_SETUP.md
echo - Usage examples: USAGE_EXAMPLES.md
echo - Security: SECURITY_CHECKLIST.md
echo.
echo IMPORTANT:
echo - Backup your encryption keys (%%USERPROFILE%%\.chat_config\file_keys.json)
echo - Never share your Dropbox credentials
echo - Review SECURITY_CHECKLIST.md before production use
echo.
pause