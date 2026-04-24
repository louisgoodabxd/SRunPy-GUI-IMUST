@echo off
chcp 65001 >nul 2>&1
title SRunPy-GUI 编译工具 (PyInstaller)

echo ============================================
echo   SRunPy-GUI 校园网登录器 编译工具
echo   编译引擎: PyInstaller (无需 C 编译器)
echo ============================================
echo.

:: ============================================
:: 第1步: 检查 Python
:: ============================================
echo [1/5] 检查 Python 环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到 Python，请先安装 Python 3.8-3.12
    echo 下载地址: https://www.python.org/downloads/
    echo 安装时请勾选 "Add Python to PATH"
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do set PYVER=%%i
echo       找到 %PYVER%
echo.

:: ============================================
:: 第2步: 安装依赖
:: ============================================
echo [2/5] 安装依赖包...
echo       (首次运行较慢，后续会跳过)
echo.
pip install requests pycryptodome pystray pywebview pywin32 win10toast Pillow pyinstaller --quiet 2>nul
if %errorlevel% neq 0 (
    echo [警告] 部分依赖安装失败，尝试继续...
)
echo       依赖安装完成
echo.

:: ============================================
:: 第3步: 生成入口文件
:: ============================================
echo [3/5] 生成加密入口文件...
echo.

:: 生成随机 AES 密钥 (16位字母数字)
set "AESKEY="
for /f "delims=" %%A in ('python -c "import random,string;print(''.join(random.choices(string.ascii_letters+string.digits,k=16)))"') do set AESKEY=%%A

if "%AESKEY%"=="" (
    echo [错误] 无法生成密钥
    pause
    exit /b 1
)

:: 写入入口文件 (在项目根目录)
(
    echo from srunpy.entry import Gui
    echo Gui^('%AESKEY%'^)
) > "%~dp0SRunClient.py"

echo       密钥已生成并写入入口文件
echo.

:: ============================================
:: 第4步: 编译 (PyInstaller)
:: ============================================
echo [4/5] 开始编译 (通常需要 1-3 分钟)...
echo       请耐心等待，不要关闭此窗口
echo.
echo ----------------------------------------

cd /d "%~dp0"

:: 使用 spec 文件编译 (单文件模式)
pyinstaller --clean --noconfirm srun_client.spec

echo ----------------------------------------
echo.
echo.

:: ============================================
:: 第5步: 检查结果
:: ============================================
echo [5/5] 检查编译结果...

if exist "%~dp0dist\SRunClient.exe" (
    echo.
    echo ============================================
    echo   编译成功!
    echo ============================================
    echo.
    echo   可执行文件位置:
    echo   %~dp0dist\SRunClient.exe
    echo.
    echo   使用说明:
    echo   1. 将 SRunClient.exe 复制到目标电脑
    echo   2. 双击即可运行
    echo   3. 首次运行会自动创建配置文件
    echo   4. 配置文件位于: %%APPDATA%%\SRunPy\config.json
    echo.
    echo   注意: 请删除 SRunClient.py 以保护加密密钥
    echo.

    :: 清理临时文件
    if exist "%~dp0build" rmdir /s /q "%~dp0build"
    if exist "%~dp0SRunClient.spec" del /q "%~dp0SRunClient.py"

    set /p OPEN="是否打开输出文件夹? (Y/n): "
    if /i not "%OPEN%"=="n" (
        explorer "%~dp0dist"
    )
) else (
    echo.
    echo ============================================
    echo   编译失败!
    echo ============================================
    echo.
    echo   可能的原因:
    echo   1. Python 版本不兼容 (推荐 3.10-3.12)
    echo   2. 依赖包未正确安装
    echo   3. 权限不足 (尝试以管理员身份运行)
    echo.
    echo   解决方案:
    echo   - 重新安装依赖: pip install requests pycryptodome pystray pywebview pywin32 win10toast Pillow pyinstaller
    echo   - 查看上方的错误信息
    echo.
)

echo.
pause
