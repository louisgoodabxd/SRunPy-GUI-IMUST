@echo off
chcp 65001 >nul 2>&1
title SRunPy-GUI 编译工具 (PyInstaller)

echo ============================================
echo   SRunPy-GUI 校园网登录器 编译工具
echo   编译引擎: PyInstaller
echo ============================================
echo.

:: 生成随机 AES 密钥
set "AESKEY="
for /f "delims=" %%A in ('python -c "import random,string;print(''.join(random.choices(string.ascii_letters+string.digits,k=16)))"') do set AESKEY=%%A

if "%AESKEY%"=="" (
    echo [错误] 无法生成密钥
    pause
    exit /b 1
)

echo AES Key: %AESKEY%
echo.

:: 生成入口文件
(
    echo from srunpy.entry import Gui
    echo Gui^('%AESKEY%'^)
) > SRunClient.py

echo 入口文件已生成
echo 开始编译...
echo.

:: 使用 PyInstaller 编译
pyinstaller --clean --noconfirm srun_client.spec

echo.
if exist "dist\SRunClient.exe" (
    echo ============================================
    echo   编译成功!
    echo   输出: dist\SRunClient.exe
    echo ============================================
) else (
    echo ============================================
    echo   编译失败!
    echo ============================================
)

pause
