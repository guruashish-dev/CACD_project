@echo off
REM Offline demonstration model - no sockets, pure simulation.
REM Produces a console timeline and opens an HTML threat-intel report.
REM Usage: scripts\demo_model.bat [--steps 200] [--seed 42] [--speed 0.05]
cd /d "%~dp0.."
python demo\demo_model.py %*
echo.
pause
