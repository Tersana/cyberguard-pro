@echo off
echo ========================================
echo    Stopping CyberGuard XSS Services
echo ========================================
echo.

echo [1/2] Stopping ZAP container...
docker stop $(docker ps -q --filter ancestor=zaproxy/zap-stable) 2>nul
if %errorlevel% equ 0 (
    echo SUCCESS: ZAP container stopped.
) else (
    echo INFO: No ZAP container was running.
)

echo [2/2] Stopping Proxy Server...
taskkill /f /im node.exe 2>nul
if %errorlevel% equ 0 (
    echo SUCCESS: Proxy server stopped.
) else (
    echo INFO: No proxy server was running.
)

echo.
echo ========================================
echo    All Services Stopped!
echo ========================================
echo.
pause


