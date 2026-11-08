@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title KJAGU // Anti-Spyware & Endpoint Threat Hunter
cd /d "%~dp0"

echo.
echo   ========================================================================
echo      KJAGU // Anti-Spyware ^& Endpoint Threat Hunter v3.1
echo      Absolute Immortal Inc. -- Defensive Security Research
echo      100%% Free ^& Local -- Zero API Keys Required
echo   ========================================================================
echo.

REM 1. Check for Python
where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    where py >nul 2>nul
    if %ERRORLEVEL% neq 0 (
        echo   [!] ERROR: Python is not installed or not in your system PATH.
        echo       Please install Python 3.10+ from https://python.org
        echo       Be sure to check "Add Python to PATH" during installation.
        echo.
        pause
        exit /b 1
    ) else (
        set "PY_CMD=py -3"
    )
) else (
    set "PY_CMD=python"
)

REM 2. Check and install core dependencies
%PY_CMD% -c "import psutil" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo   [*] First run detected. Installing dependencies from requirements.txt...
    %PY_CMD% -m pip install -r requirements.txt
    if %ERRORLEVEL% neq 0 (
        echo   [!] Warning: Some dependencies failed to install. Launching with available modules...
    )
)

echo   [*] Launching Kjagu Engine...
echo.

%PY_CMD% kjagu_core.py %*

if %ERRORLEVEL% neq 0 (
    echo.
    echo   [!] Kjagu exited with error code %ERRORLEVEL%.
    pause
)
