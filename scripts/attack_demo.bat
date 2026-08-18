@echo off
REM Live demo: start the real honeypots, then fire real attacks at them.
REM Usage: scripts\attack_demo.bat [--plan sweep|targeted|stealth]
cd /d "%~dp0.."

echo Starting honeypot network in a new window...
start "Honeypot Network" /D "%~dp0.." cmd /k "python main.py"

echo Waiting for honeypots to bind...
timeout /t 3 /nobreak >nul

echo Firing attack plan: %1
python demo\attack_simulator.py %*
echo.
echo Done. Watch the honeypot console and open http://127.0.0.1:8080 for the dashboard.
pause
