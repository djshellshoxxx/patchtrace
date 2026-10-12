"""Collect desktop-only QtGui plugins before DLL dependency traversal.

PatchTrace uses built-in text and vector painting. External image codecs,
virtual keyboards and alternative platform backends are not application features.
"""
from pathlib import Path

from PyInstaller.utils.hooks.qt import pyside6_library_info

hiddenimports, binaries, datas = pyside6_library_info.collect_module('PySide6.QtGui')
# Windows rendering, Linux X11/Wayland rendering, and the offscreen smoke-test backend.
allowed_plugins = {'qwindows.dll', 'qoffscreen.dll', 'libqoffscreen.so', 'libqxcb.so',
                   'libqwayland-egl.so', 'libqwayland-generic.so', 'libqwayland.so'}
# Linux platform plugins load these integration plugin directories at runtime.
allowed_dirs = {'xcbglintegrations', 'wayland-shell-integration', 'wayland-graphics-integration-client',
                'wayland-decoration-client'}


def _keep(source, destination):
    parts = Path(destination).parts
    if 'plugins' not in parts:
        return True
    return Path(source).name.lower() in allowed_plugins or any(part in allowed_dirs for part in parts)


binaries = [(source, destination) for source, destination in binaries if _keep(source, destination)]
