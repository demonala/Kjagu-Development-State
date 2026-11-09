@echo off
setlocal enabledelayedexpansion

title KJAGU // Native Messaging Host Registration
echo.
echo   ========================================================================
echo      KJAGU // Native Messaging Bridge Installer
echo      Absolute Immortal Inc. -- Defensive Security Research
echo   ========================================================================
echo.

set "HOST_NAME=com.kjagu.ridit"
set "BRIDGE_DIR=%~dp0"
set "MANIFEST_PATH=%BRIDGE_DIR%host_manifest.json"
set "BAT_PATH=%BRIDGE_DIR%kjagu_bridge.bat"

:: Update host_manifest.json path dynamically using Python
python -c "import json; p=r'%MANIFEST_PATH%'; d=json.load(open(p, 'r', encoding='utf-8')); d['path']=r'%BAT_PATH%'; json.dump(d, open(p, 'w', encoding='utf-8'), indent=2)"

if %ERRORLEVEL% neq 0 (
    echo   [!] Warning: Could not update absolute path in host_manifest.json.
) else (
    echo   [+] Configured bridge path: %BAT_PATH%
)

:: Register for Google Chrome
reg add "HKCU\Software\Google\Chrome\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST_PATH%" /f >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   [+] Registered for Google Chrome
)

:: Register for Brave Browser
reg add "HKCU\Software\BraveSoftware\Brave-Browser\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST_PATH%" /f >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   [+] Registered for Brave Browser
)

:: Register for Microsoft Edge
reg add "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST_PATH%" /f >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   [+] Registered for Microsoft Edge
)

:: Register for Chromium
reg add "HKCU\Software\Chromium\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST_PATH%" /f >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo   [+] Registered for Chromium
)

echo.
echo   [+] Native messaging host registered successfully: %HOST_NAME%
echo   [+] Manifest: %MANIFEST_PATH%
echo.
