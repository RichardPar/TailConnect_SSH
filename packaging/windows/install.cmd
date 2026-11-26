@echo off
rem Install (or upgrade) TailConnect-SSH from this folder. Windows asks for administrator rights.
"%~dp0tcd.exe" install %*
echo.
pause
