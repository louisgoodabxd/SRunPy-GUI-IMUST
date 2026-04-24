"""
WebRoot 路径解析模块
自动适配: 开发环境 / pip 安装 / PyInstaller 打包
"""
import sys
import os
from os import path


def _get_webroot() -> str:
    """
    获取 html 静态资源目录路径。
    优先级:
      1. PyInstaller 打包后的 sys._MEIPASS/srunpy/html
      2. importlib.resources (pip 安装 / 开发环境)
      3. 回退到当前文件所在目录
    """
    # PyInstaller 打包后的路径
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        candidate = path.join(sys._MEIPASS, 'srunpy', 'html')
        if path.isdir(candidate):
            return candidate

    # 标准 importlib.resources 方式
    try:
        import importlib.resources
        from srunpy import html as html_pkg
        with importlib.resources.path(html_pkg, 'index.html') as HtmlFile:
            candidate = path.dirname(str(HtmlFile))
            if path.isdir(candidate):
                return candidate
    except Exception:
        pass

    # 回退: 当前文件的同级目录 (开发环境)
    return path.dirname(path.abspath(__file__))


WebRoot = _get_webroot()
