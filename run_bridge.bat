@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title KJAGU // Browser Shield & Native Messaging Bridge
cd /d "%~dp0"

echo.
echo   ========================================================================
echo      KJAGU // Browser Shield & Native Messaging Bridge v4.0
echo      Absolute Immortal Inc. -- Defensive Security Research
echo      Zero API Keys Required -- Free DeepSeek / Kimi Chat Integration
echo   ========================================================================
echo.

:: 1. Check Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo   [!] ERROR: Python is not installed or not in PATH.
    pause
    exit /b 1
)

:: 2. Register native messaging host
call "%~dp0bridge\install_host.bat"

:: 3. Setup Reports Directory
if not exist "%USERPROFILE%\Desktop\KjaguReports" (
    mkdir "%USERPROFILE%\Desktop\KjaguReports"
    echo   [+] Created report destination: %USERPROFILE%\Desktop\KjaguReports
)

echo.
echo   HOW TO LOAD THE EXTENSION:
echo   ------------------------------------------------------------------------
echo   1. Open Chrome, Brave, or Edge.
echo   2. Navigate to: chrome://extensions (or brave://extensions / edge://extensions)
echo   3. Enable "Developer mode" toggle.
echo   4. Click "Load unpacked".
echo   5. Select the folder: %~dp0extension
echo   6. Open chat.deepseek.com or kimi.moonshot.cn to interact with the shield!
echo   ------------------------------------------------------------------------
echo.
echo   [!] Note: Chrome will automatically launch the bridge via Native Messaging.
echo   [!] You can also test the bridge manually below. Press Ctrl+C to stop.
echo.
echo   Starting Kjagu Native Bridge...
echo.

python "%~dp0bridge\kjagu_bridge.py"

pause
