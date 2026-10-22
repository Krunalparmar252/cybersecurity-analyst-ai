@echo off
cd /d "%~dp0"
"%~dp0.venv\Scripts\pytest.exe" tests\ -v > "%TEMP%\ptout.txt" 2>&1
echo Exit code: %ERRORLEVEL%
type "%TEMP%\ptout.txt"
