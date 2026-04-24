@echo off
chcp 65001 >nul 2>&1
title SRunPy-GUI 编译工具

echo ============================================
echo   SRunPy-GUI 校园网登录器 编译工具
echo   适用于: 内蒙古科技大学 (IMUST)
echo ============================================
echo.

:: ============================================
:: 第1步: 检查 Python
:: ============================================
echo [1/5] 检查 Python 环境...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到 Python，请先安装 Python 3.7+
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
pip install requests pycryptodome pystray pywebview pywin32 win10toast nuitka ordered-set zstandard --quiet 2>nul
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

:: 创建编译输出目录
if not exist "%~dp0SrunPy_Output" mkdir "%~dp0SrunPy_Output"

:: 写入入口文件
(
    echo from srunpy.entry import Gui
    echo Gui^('%AESKEY%'^)
) > "%~dp0SrunPy_Output\SRunClient.py"

echo       密钥已生成并写入入口文件
echo       输出目录: %~dp0SrunPy_Output
echo.

:: ============================================
:: 第4步: 编译
:: ============================================
echo [4/5] 开始编译 (可能需要 3-10 分钟)...
echo       请耐心等待，不要关闭此窗口
echo.
echo ----------------------------------------

cd /d "%~dp0SrunPy_Output"

python -m nuitka --lto=no --standalone SRunClient.py --include-data-dir="%~dp0srunpy\html"=srunpy/html --windows-console-mode=attach --windows-icon-from-ico="%~dp0srunpy\html\icons\logo.ico" --file-version="1.0.9.1" --product-version="1.0.9.1" --company-name="IMUST" --product-name="IMUST Campus Login" --file-description="IMUST Campus Network Login Client"

echo ----------------------------------------
echo.

:: ============================================
:: 第5步: 检查结果
:: ============================================
echo [5/5] 检查编译结果...

if exist "%~dp0SrunPy_Output\SRunClient.dist\SRunClient.exe" (
    echo.
    echo ============================================
    echo   编译成功!
    echo ============================================
    echo.
    echo   可执行文件位置:
    echo   %~dp0SrunPy_Output\SRunClient.dist\SRunClient.exe
    echo.
    echo   使用说明:
    echo   1. 将 SRunClient.dist 整个文件夹复制到目标电脑
    echo   2. 双击 SRunClient.exe 即可运行
    echo   3. 首次运行会自动创建配置文件
    echo   4. 配置文件位于: %%APPDATA%%\SRunPy\config.json
    echo.
    echo   注意: 请删除 SRunClient.py 以保护加密密钥
    echo.
    set /p OPEN="是否打开输出文件夹? (Y/n): "
    if /i not "%OPEN%"=="n" (
        explorer "%~dp0SrunPy_Output\SRunClient.dist"
    )
) else (
    echo.
    echo ============================================
    echo   编译失败!
    echo ============================================
    echo.
    echo   可能的原因:
    echo   1. Python 版本不兼容 (推荐 3.10-3.12)
    echo   2. 缺少 C 编译器 (需要 Visual Studio Build Tools)
    echo   3. 依赖包未正确安装
    echo.
    echo   解决方案:
    echo   - 安装 Visual Studio Build Tools:
    echo     https://visualstudio.microsoft.com/visual-cpp-build-tools/
    echo   - 安装时选择 "C++ 桌面开发" 工作负载
    echo.
)

echo.
pause
