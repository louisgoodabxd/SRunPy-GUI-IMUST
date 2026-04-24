# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for SRunPy-GUI (IMUST)
使用 PyInstaller 打包校园网登录器

用法:
  pyinstaller srun_client.spec
"""

import os
import sys

block_cipher = None

# 项目根目录
ROOT = os.path.dirname(os.path.abspath(SPEC))

# 收集 srunpy 包的所有数据文件 (html, css, js, 图标, 字体等)
srunpy_datas = []
html_dir = os.path.join(ROOT, 'srunpy', 'html')
if os.path.isdir(html_dir):
    for dirpath, dirnames, filenames in os.walk(html_dir):
        for fn in filenames:
            src = os.path.join(dirpath, fn)
            # 目标路径保持 srunpy/html/... 的相对结构
            dst = os.path.relpath(dirpath, ROOT)
            srunpy_datas.append((src, dst))

a = Analysis(
    # 入口文件：编译时由 build 脚本生成，包含 AES 密钥
    ['SRunClient.py'],
    pathex=[ROOT],
    binaries=[],
    datas=srunpy_datas,
    hiddenimports=[
        # pywebview 后端
        'webview',
        'webview.platforms',
        'webview.platforms.edgechromium',
        'webview.platforms.mshtml',
        'webview.platforms.winforms',
        'webview.window',
        'webview.util',
        'webview.js.api',
        'webview.js.css',
        # pystray 后端
        'pystray',
        'pystray._win32',
        'pystray._base',
        # pywin32
        'win32api',
        'win32gui',
        'win32con',
        'win32com',
        'win32com.client',
        'pywintypes',
        'pythoncom',
        # PIL / Pillow (pystray 依赖)
        'PIL',
        'PIL.Image',
        # win10toast
        'win10toast',
        # pycryptodome
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Cipher.AES',
        # requests
        'requests',
        'urllib3',
        'certifi',
        'charset_normalizer',
        'idna',
        # 标准库
        'json',
        'threading',
        'socket',
        'ctypes',
        'ctypes.wintypes',
        'subprocess',
        'webbrowser',
        'argparse',
        'base64',
        'hashlib',
        'hmac',
        'logging',
        'uuid',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # 排除不需要的模块以减小体积
        'tkinter',
        'matplotlib',
        'numpy',
        'scipy',
        'pandas',
        'pytest',
    ],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

# 单文件模式 (onefile) — 生成单个 exe
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SRunClient',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # 保留控制台以显示日志，也可改为 False
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, 'srunpy', 'html', 'icons', 'logo.ico'),
)
