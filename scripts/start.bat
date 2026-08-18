@echo off
REM Start the real honeypot network + live dashboard.
REM Usage: scripts\start.bat [--protocols ssh,http] [--no-dashboard] [--dashboard-port 9000]
cd /d "%~dp0.."
echo Starting Multi-Protocol Honeypot Network...
echo Dashboard will be at http://127.0.0.1:8080  (press Ctrl-C to stop)
echo.
python main.py %*
pause
