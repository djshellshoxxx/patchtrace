# Linux x86-64 standalone

Build on Linux only: `python tools/build_linux.py` (Python 3.12 venv with `.[dev]`). Output: `dist/PatchTrace-0.1.0-linux-x86_64.tar.gz` and `.sha256`. CI builds on Ubuntu 22.04 (older glibc baseline) and smoke-tests the extracted archive on Ubuntu 22.04 and 24.04, offscreen and under Xvfb/xcb.

Bundled: Python, PySide6/Qt (xcb, Wayland, offscreen platform plugins), PatchTrace, licenses. tar.gz preserves the executable bit.

Host prerequisites (not bundled): `libegl1 libgl1 libxcb-cursor0 libxkbcommon-x11-0` for X11 (Qt 6.5+ xcb needs `libxcb-cursor0`), or a Wayland session. Ghidra, Java and Ghidriff stay external, as on Windows.

Run: `tar xzf PatchTrace-0.1.0-linux-x86_64.tar.gz && ./PatchTrace/PatchTrace`. Smoke test: `QT_QPA_PLATFORM=offscreen ./PatchTrace/PatchTrace --self-test`.

Verified locally (Ubuntu 24.04 container): offscreen and Xvfb/xcb `--self-test` pass from the extracted archive. Live Ghidriff analysis from the frozen Linux build is not yet verified.
