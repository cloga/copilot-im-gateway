@echo off
setlocal
cd /d "%~dp0app"
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%~dp0credential-key.ps1" -NodePath "%~dp0runtime\node.exe" -EntryPoint "%~dp0app\dist\daemon\main.js" -MaintenanceEntryPoint "%~dp0app\dist\daemon\maintenance.js"
