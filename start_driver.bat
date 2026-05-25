@echo off
echo Starting Wintun driver...
sc start wintun
if %errorlevel% neq 0 (
    echo.
    echo Failed to start driver. Make sure you're running as Administrator!
    echo Right-click this file and select "Run as administrator"
    pause
    exit /b 1
)
echo.
echo Driver started successfully!
echo Now run: py -3.12 test_tun.py
pause