# Linux x86-64 standalone

Build on Linux only: `python tools/build_linux.py` (Python 3.12 venv with `.[dev]`). Output: `dist/PatchTrace-0.1.0-linux-x86_64.tar.gz` and `.sha256`. CI builds on Ubuntu 22.04 (older glibc baseline) and smoke-tests the extracted archive on Ubuntu 22.04 and 24.04, offscreen and under Xvfb/xcb.

Bundled: Python, PySide6/Qt (xcb, Wayland, offscreen platform plugins), PatchTrace, licenses. tar.gz preserves the executable bit.

Host prerequisites (not bundled), Debian/Ubuntu names: `libegl1 libgl1 libfontconfig1 libdbus-1-3 libxkbcommon0 libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 libxcb-xfixes0` for X11 (Qt 6.5+ xcb needs `libxcb-cursor0`), or a Wayland session. Without them the xcb plugin aborts with `Could not load the Qt platform plugin "xcb"`; `ldd PatchTrace/_internal/PySide6/Qt/lib/libQt6XcbQpa.so.6 | grep 'not found'` lists what is missing. Ghidra, Java and Ghidriff stay external, as on Windows.

Run: `tar xzf PatchTrace-0.1.0-linux-x86_64.tar.gz && ./PatchTrace/PatchTrace`. Smoke test: `QT_QPA_PLATFORM=offscreen ./PatchTrace/PatchTrace --self-test`.

Verified locally 2026-10-12 (Ubuntu container, clean `env -i`): checksum, exec bit and offscreen `--self-test` pass from the extracted archive; xcb aborts when `libxcb-cursor0` is absent, as expected. Live Ghidriff analysis from the frozen Linux build is not yet verified.
