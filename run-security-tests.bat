@echo off
echo 🧪 CyberGuard Pro - Security Functions Test Runner
echo ================================================
echo.

echo 📡 Starting security functions tests...
echo.

REM Check if Node.js is installed
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed or not in PATH
    echo Please install Node.js from https://nodejs.org
    pause
    exit /b 1
)

REM Check if web server is running
echo 🔍 Checking if web server is running...
curl -s http://localhost:3000 >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Web server is not running on localhost:3000
    echo Please start your web server first:
    echo   cd D:\Code\CyberGuardWeb
    echo   http-server -p 3000
    echo.
    pause
    exit /b 1
)

echo ✅ Web server is running
echo.

REM Run the tests
echo 🚀 Running security functions tests...
node test-security-functions.js

echo.
echo 📊 Security tests completed!
echo.
pause

