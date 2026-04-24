@echo off
chcp 65001 >nul 2>&1
title SRunPy Build Tool

:: pushd can map UNC paths (\\wsl.localhost\...) to a temp drive letter
pushd "%~dp0"
if %errorlevel% neq 0 (
    echo [ERROR] Cannot access project directory.
    echo Please copy the SRunPy-GUI folder to a Windows path first.
    echo e.g. C:\Users\%USERNAME%\Desktop\SRunPy-GUI
    pause
    exit /b 1
)

echo ============================================
echo   SRunPy-GUI Build Tool (PyInstaller)
echo   No C compiler needed!
echo ============================================
echo.
echo   Working dir: %CD%
echo.

:: Step 1: Check Python
echo [1/5] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found.
    echo Download: https://www.python.org/downloads/
    echo Check "Add Python to PATH" during install.
    popd
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo       Found: %PYVER%
echo.

:: Step 2: Install dependencies
echo [2/5] Installing dependencies (first time is slow)...
pip install requests pycryptodome pystray pywebview pywin32 win10toast Pillow pyinstaller --quiet 2>nul
if %errorlevel% neq 0 (
    echo [WARNING] Some packages failed, trying to continue...
)
echo       Done
echo.

:: Step 3: Generate entry file
echo [3/5] Generating entry file with AES key...
set "AESKEY="
for /f "delims=" %%A in ('python -c "import random,string;print(''.join(random.choices(string.ascii_letters+string.digits,k=16)))"') do set AESKEY=%%A
if "%AESKEY%"=="" (
    echo [ERROR] Failed to generate key
    popd
    pause
    exit /b 1
)

(
    echo from srunpy.entry import Gui
    echo Gui^('%AESKEY%'^)
) > "SRunClient.py"
echo       Key: %AESKEY%
echo       Entry file: SRunClient.py
echo.

:: Step 4: Build
echo [4/5] Building with PyInstaller (1-3 min, please wait)...
echo.
echo --------------------------------------------------
pyinstaller --clean --noconfirm srun_client.spec
echo --------------------------------------------------
echo.

:: Step 5: Check result
echo [5/5] Checking result...
echo.

if exist "dist\SRunClient.exe" (
    echo ============================================
    echo   BUILD SUCCESSFUL!
    echo ============================================
    echo.
    echo   File: %CD%\dist\SRunClient.exe
    for %%F in ("dist\SRunClient.exe") do echo   Size: %%~zF bytes
    echo.
    echo   Usage:
    echo     1. Copy SRunClient.exe to target PC
    echo     2. Double-click to run
    echo     3. Config: %%APPDATA%%\SRunPy\config.json
    echo.
    echo   Tip: Delete SRunClient.py to protect your AES key
    echo.

    :: Cleanup
    if exist "build" rmdir /s /q "build"
    del /q "SRunClient.py" 2>nul

    set /p OPEN="Open output folder? (Y/n): "
    if /i not "%OPEN%"=="n" (
        start "" "%CD%\dist"
    )
) else (
    echo ============================================
    echo   BUILD FAILED
    echo ============================================
    echo.
    echo   Check the error messages above.
    echo   Common fixes:
    echo     - Use Python 3.10-3.12
    echo     - pip install pyinstaller
    echo     - Run as Administrator
    echo.
)

popd
pause
