@echo off
echo.
echo ====================================================
echo   BYMA TOOLS - Installation Script
echo   Multi-Purpose Cybersecurity Toolkit
echo ====================================================
echo.

echo [1/3] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found!
    echo Please install Python 3.8+ from https://python.org
    pause
    exit /b 1
)
echo [OK] Python found
echo.

echo [2/3] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies
    pause
    exit /b 1
)
echo.

echo [3/3] Setting up directories...
if not exist "database" mkdir database
if not exist "output" mkdir output
if not exist "output\reports" mkdir output\reports
if not exist "wordlists" mkdir wordlists
echo.

echo ====================================================
echo   Installation Complete!
echo ====================================================
echo.
echo Usage:
echo   python main.py --help
echo   python main.py auto http://target.com
echo.
echo For more information, see README.md
echo.
pause
