# Linux x86-64 standalone

Build on Linux only: `python tools/build_linux.py` (Python 3.12 venv with `.[dev]`). Output: `dist/PatchTrace-0.1.0-linux-x86_64.tar.gz` and `.sha256`. CI builds on Ubuntu 22.04 (older glibc baseline) and smoke-tests the extracted archive on Ubuntu 22.04 and 24.04, offscreen and under Xvfb/xcb.

Bundled: Python, PySide6/Qt (xcb, Wayland, offscreen platform plugins), PatchTrace, licenses. tar.gz preserves the executable bit.

Host prerequisites (not bundled), Debian/Ubuntu names: `libegl1 libgl1 libfontconfig1 libdbus-1-3 libxkbcommon0 libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 libxcb-xfixes0` for X11 (Qt 6.5+ xcb needs `libxcb-cursor0`), or a Wayland session. Without them the xcb plugin aborts with `Could not load the Qt platform plugin "xcb"`; `ldd PatchTrace/_internal/PySide6/Qt/lib/libQt6XcbQpa.so.6 | grep 'not found'` lists what is missing. Ghidra, Java and Ghidriff stay external, as on Windows.

Run: `tar xzf PatchTrace-0.1.0-linux-x86_64.tar.gz && ./PatchTrace/PatchTrace`. Smoke test: `QT_QPA_PLATFORM=offscreen ./PatchTrace/PatchTrace --self-test`.

Verified locally 2026-10-12 (Ubuntu container, clean `env -i`): checksum, exec bit and offscreen `--self-test` pass from the extracted archive; xcb aborts when `libxcb-cursor0` is absent, as expected. Live Ghidriff analysis from the frozen Linux build is not yet verified.


## Frozen Linux CLI smoke acceptance (CODEX-14)

The `linux-smoke` matrix must test the **extracted, checksum-verified onedir Linux
archive** on both Ubuntu 22.04 and Ubuntu 24.04, not just `python -m patchtrace`
from a development installation or the pre-archive build tree. Continue to require
both the offscreen and Xvfb/xcb `--self-test` probes. Run the existing
`tools/frozen_smoke.py` harness against the extracted
`PatchTrace/PatchTrace` executable in an offscreen environment. Its host-side
synthetic project and BinExport/CSAF fixtures may use the exact checked-out
source and declared Python dependencies; only the frozen executable under test
may satisfy the CLI checks. Do not execute submitted target binaries, live
Ghidra analyses, third-party installers or network acquisition.

The harness must fail the job if any top-level command help, refusal, JSON
report, synthetic series, stored-intelligence, secondary-worker or included-data
check fails. Retain the preexisting archive SHA-256 and executable-bit checks,
both GUI-platform modes, and source/CI SHA binding. Do not weaken the static
CODEX-14 regression or claim nested-subcommand coverage: `names()` covers
top-level verbs, with nested parser behavior only where the harness explicitly
tests it. A green static regression alone is **not** frozen Linux acceptance.
Acceptance requires passing source-specific hosted `linux-smoke` jobs on both
distributions and a review that the executable exercised was from the same
archive as the packaged release candidate.

Until those jobs and applicable QA/Qt/native/package checks are green,
CODEX-14 is implemented-but-unqualified and release readiness remains false.
