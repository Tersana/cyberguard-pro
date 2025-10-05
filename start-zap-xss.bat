@echo off
echo ========================================
echo    CyberGuard XSS Scanner Startup
echo ========================================
echo.

echo [1/4] Starting OWASP ZAP...
docker run -d -p 8080:8080 -i zaproxy/zap-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true
if %errorlevel% neq 0 (
    echo ERROR: Failed to start ZAP. Make sure Docker is running.
    pause
    exit /b 1
)

echo [2/4] Waiting for ZAP to initialize (30 seconds)...
timeout /t 30 /nobreak >nul

echo [3/4] Testing ZAP connection...
curl -s http://localhost:8080/JSON/core/view/version/ >nul
if %errorlevel% neq 0 (
    echo WARNING: ZAP might still be starting. Please wait a bit more.
) else (
    echo SUCCESS: ZAP is running and accessible!
)

echo [4/4] Starting Proxy Server...
echo.
echo Starting proxy server on port 3001...
echo Press Ctrl+C to stop the proxy server when done.
echo.
start "ZAP Proxy Server" cmd /k "npm start"

echo.
echo ========================================
echo    Setup Complete!
echo ========================================
echo.
echo ZAP is running on: http://localhost:8080
echo Proxy is running on: http://localhost:3001
echo.
echo You can now use your XSS scanner!
echo.
pause


