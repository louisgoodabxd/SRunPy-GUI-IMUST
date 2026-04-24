# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for SRunPy-GUI (IMUST) — 文件夹模式
使用 PyInstaller 打包校园网登录器 (输出为文件夹而非单文件)

用法:
  pyinstaller srun_client_folder.spec
"""

import os
import sys

block_cipher = None

ROOT = os.path.dirname(os.path.abspath(SPEC))

# 收集 srunpy 包的所有数据文件
srunpy_datas = []
html_dir = os.path.join(ROOT, 'srunpy', 'html')
if os.path.isdir(html_dir):
    for dirpath, dirnames, filenames in os.walk(html_dir):
        for fn in filenames:
            src = os.path.join(dirpath, fn)
            dst = os.path.relpath(dirpath, ROOT)
            srunpy_datas.append((src, dst))

a = Analysis(
    ['SRunClient.py'],
    pathex=[ROOT],
    binaries=[],
    datas=srunpy_datas,
    hiddenimports=[
        'webview',
        'webview.platforms',
        'webview.platforms.edgechromium',
        'webview.platforms.mshtml',
        'webview.platforms.winforms',
        'webview.window',
        'webview.util',
        'webview.js.api',
        'webview.js.css',
        'pystray',
        'pystray._win32',
        'pystray._base',
        'win32api',
        'win32gui',
        'win32con',
        'win32com',
        'win32com.client',
        'pywintypes',
        'pythoncom',
        'PIL',
        'PIL.Image',
        'win10toast',
        'Crypto',
        'Crypto.Cipher',
        'Crypto.Cipher.AES',
        'requests',
        'urllib3',
        'certifi',
        'charset_normalizer',
        'idna',
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

exe = EXE(
    pyz,
    a.scripts,
    [],
    name='SRunClient',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    exclude_binaries=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=os.path.join(ROOT, 'srunpy', 'html', 'icons', 'logo.ico'),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='SRunClient',
)
