@echo off
setlocal
cd /d "%~dp0app"
"%~dp0runtime\node.exe" "%~dp0app\dist\daemon\main.js"
