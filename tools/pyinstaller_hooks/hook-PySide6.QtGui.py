"""Collect desktop-only QtGui plugins before DLL dependency traversal.

PatchTrace uses built-in text and vector painting. External image codecs,
virtual keyboards and alternative platform backends are not application features.
"""
from pathlib import Path

from PyInstaller.utils.hooks.qt import pyside6_library_info

hiddenimports, binaries, datas = pyside6_library_info.collect_module('PySide6.QtGui')
# Keep Windows rendering and the automated offscreen smoke-test backend.
allowed_plugins = {'qwindows.dll', 'qoffscreen.dll'}
binaries = [(source, destination) for source, destination in binaries
            if 'plugins' not in Path(destination).parts or Path(source).name.lower() in allowed_plugins]
