"""
SRunPy - Third-party Srun Gateway Authentication Client
深澜网关第三方认证客户端

This package provides functionality to authenticate with Srun gateway systems.
本包提供深澜网关系统的认证功能。
"""

import os
import platform
import sys
from typing import Tuple

# PyInstaller frozen mode: redirect stdout/stderr to devnull to prevent console window
if getattr(sys, 'frozen', False):
    _devnull = open(os.devnull, 'w')
    sys.stdout = _devnull
    sys.stderr = _devnull

# Version information / 版本信息
PROGRAM_VERSION: Tuple[int, int, int, int] = (1, 0, 9, 1)
__version__: str = '.'.join(map(str, PROGRAM_VERSION))

# Import core components / 导入核心组件
from .html import WebRoot  # noqa: E402, F401
from .srun import Srun_Py as SrunClient  # noqa: E402, F401

# Import Windows-specific components / 导入 Windows 特定组件
if platform.system() == 'Windows':
    from .interface import MainWindow, TaskbarIcon, GUIBackend  # noqa: E402, F401

print('SrunClient version:', __version__)
