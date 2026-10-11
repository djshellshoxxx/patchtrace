# Windows package notice audit (source-only)

Checked 2026-10-11 against the source tree and locally installed package metadata. This audit adds upstream license texts and records their exact source revisions. It does **not** inspect a Windows build, PyInstaller analysis/TOC, final ZIP, or Qt DLL dependency tree; no claim is made that the final package's notice set is complete.

## Source evidence

- **PySide6/Shiboken 6.12.0:** official Qt for Python repository tag `v6.12.0`, peeled commit `f50facb83fc3dc5f3240c854668c7a6dd93871b2`. The copied `LICENSES/` directory is from that tag. The source also has `sources/pyside6/COPYING`, `sources/pyside6/PySide6/licensecomment.txt`, `sources/shiboken6/COPYING`, and `sources/shiboken6/COPYING.libshiboken`; copies are retained with source-specific names under [third_party/notices](../third_party/notices/README.md). The tag's license comment and the locally inspected wheel metadata describe LGPL-3.0-only/GPL-2.0-only/GPL-3.0-only alternatives; some source files also carry historical LGPL-2.1/GPL-2.0 texts. This audit preserves those upstream texts without assigning a legal interpretation to each binary.
- **Qt 6.12.0:** official `qtbase` tag `v6.12.0`, peeled commit `025bdad181de241e81bf853c8a2d7bf3d19261a9`. Its `LICENSES/` directory is copied under `third_party/notices/qtbase-6.12.0/`. Qt's [Qt 6.12 third-party code index](https://doc.qt.io/qt-6.12/licenses-used-in-qt.html) lists components by Qt module, including Qt Core and Qt GUI. It is a source inventory, not proof of which optional Qt modules or plugins are in PatchTrace.
- **PyInstaller:** official tag `v6.22.3`, commit `ecd7993d65c43b254f4e3f718e36d5b4a70a3ed5`. Its `COPYING.txt` was copied to `third_party/notices/pyinstaller-6.22.3/`; the file hash matches the installed PyInstaller distribution inspected here. PyInstaller's source identifies GPL-2.0-or-later with a bootloader exception.

The full path mapping and Qt source metadata are in [third_party/notices/README.md](../third_party/notices/README.md). The staged Qt and PySide wheel metadata in this environment did not list license-named files, so the script's old package-file-name scan alone would not populate these upstream texts.

## Dependency and bundle limits

The project pins `PySide6==6.12.0`. In the inspected environment, the PySide6 wheel metadata required Essentials and Addons at 6.12.0, plus `PySide6_WebEngine==6.12.0.140` and `PySide6_Pdf==6.12.0.140`; WebEngine also depends on Addons and PDF on Essentials. The Windows build's package/version manifest should include those distributions or establish from the actual frozen analysis that their binaries are excluded. Pydantic's exact and lower-bounded transitive requirements also mean the resolved versions should be captured for every build.

PatchTrace source imports `PySide6.QtCore`, `QtGui`, and `QtWidgets`. That source fact cannot establish whether the PyInstaller hooks, Qt plugin collection, or implicit DLL dependencies include Qt PDF, WebEngine, or additional third-party binaries. A Windows onedir ZIP and its collected-file list are needed to make that determination and tailor notices. PyInstaller's `--onedir` command is intended to keep Qt DLLs as separate files that can be replaced; this audit did not inspect the ZIP or verify DLL replacement in a built executable.

## Release follow-up

Before release, inspect the exact Windows `dist/PatchTrace` tree and PyInstaller analysis output, record every shipped Qt DLL/module/plugin and dependency version/hash, compare that list to the official Qt 6.12 module inventory, and add any package-specific notices from the matching upstream revisions. Confirm the resulting notices are inside the ZIP, and verify the replaceable-DLL layout on the actual artifact. This remains a source-only audit until that Windows evidence exists.
