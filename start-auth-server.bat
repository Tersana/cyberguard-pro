@echo off
echo Starting CyberGuard Pro Authentication Server...
echo.

cd /d "%~dp0auth-server"

echo Installing dependencies...
call npm install

echo.
echo Starting authentication server on port 3002...
echo.
echo Server will be available at: http://localhost:3002
echo Health check: http://localhost:3002/health
echo.

call npm start

pause


