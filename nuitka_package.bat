@echo off
chcp 65001 >nul 2>&1
title SRunPy Quick Build

:: Quick build - just run PyInstaller with spec file
pushd "%~dp0"
if %errorlevel% neq 0 (
    echo [ERROR] Cannot access directory. Copy project to Windows path first.
    pause
    exit /b 1
)

echo Generating AES key and building...
set "AESKEY="
for /f "delims=" %%A in ('python -c "import random,string;print(''.join(random.choices(string.ascii_letters+string.digits,k=16)))"') do set AESKEY=%%A
(
    echo from srunpy.entry import Gui
    echo Gui^('%AESKEY%'^)
) > "SRunClient.py"

pyinstaller --clean --noconfirm srun_client.spec

if exist "dist\SRunClient.exe" (
    echo BUILD SUCCESSFUL: dist\SRunClient.exe
) else (
    echo BUILD FAILED
)
del /q "SRunClient.py" 2>nul
popd
pause
