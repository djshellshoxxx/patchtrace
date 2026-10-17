# Windows package notice audit

Checked 2026-10-11 against upstream source revisions and the final Windows CI inventory. The final package result is recorded below; Qt component notices are still mapped against the frozen inventory rather than treated as a legal conclusion.

## Source evidence

- **PySide6/Shiboken 6.12.0:** official Qt for Python repository tag `v6.12.0`, peeled commit `f50facb83fc3dc5f3240c854668c7a6dd93871b2`. The copied `LICENSES/` directory is from that tag. The source also has `sources/pyside6/COPYING`, `sources/pyside6/PySide6/licensecomment.txt`, `sources/shiboken6/COPYING`, and `sources/shiboken6/COPYING.libshiboken`; copies are retained with source-specific names under [third_party/notices](../third_party/notices/README.md). The tag's license comment and the locally inspected wheel metadata describe LGPL-3.0-only/GPL-2.0-only/GPL-3.0-only alternatives; some source files also carry historical LGPL-2.1/GPL-2.0 texts. This audit preserves those upstream texts without assigning a legal interpretation to each binary.
- **Qt 6.12.0:** official `qtbase` tag `v6.12.0`, peeled commit `025bdad181de241e81bf853c8a2d7bf3d19261a9`. Its `LICENSES/` directory is copied under `third_party/notices/qtbase-6.12.0/`. Qt's [Qt 6.12 third-party code index](https://doc.qt.io/qt-6.12/licenses-used-in-qt.html) lists components by Qt module. Official Qt Core, Qt GUI, and Qt Network attribution pages are staged in `third_party/notices/qtbase-6.12.0/attributions/`; Qt Network's Public Suffix List is identified as MPL-2.0 and libpsl as BSD-3-Clause, with both full attribution pages included.
- **PyInstaller:** official tag `v6.22.3`, commit `ecd7993d65c43b254f4e3f718e36d5b4a70a3ed5`. Its `COPYING.txt` was copied to `third_party/notices/pyinstaller-6.22.3/`; the file hash matches the installed PyInstaller distribution inspected here. PyInstaller's source identifies GPL-2.0-or-later with a bootloader exception.

The full path mapping and Qt source metadata are in [third_party/notices/README.md](../third_party/notices/README.md). The staged Qt and PySide wheel metadata in this environment did not list license-named files, so the script's old package-file-name scan alone would not populate these upstream texts.

## Final Windows artifact evidence

CI run [38127040440](https://github.com/djshellshoxxx/patchtrace/actions/runs/38127040440) reports that the frozen executable self-test, ZIP checksum, and inventory checks passed. The Windows x64 ZIP is 46,370,158 bytes with 417 archive entries; SHA-256 is `c5783e25146029a741a5450209638a15cf9f955e6e24582c04277325079e95b2`. The archive includes its own `file-inventory.json`; the audited inventory reports 351 file paths before the manifest is written.

That inventory confirms `Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Network.dll`, and `Qt6Widgets.dll`, with `qnetworklistmanager`, `qcertonlybackend`, `qopensslbackend`, `qschannelbackend`, `qmodernwindowsstyle`, `qwindows`, and `qoffscreen` plugins. It contains no Qt PDF, WebEngine, QML, Quick, or VirtualKeyboard binaries. The Qt Network attribution pages and Qtbase MPL-2.0/BSD-3-Clause texts are now included in the source notice bundle. PE version resources parsed from the frozen DLLs report OpenSSL 3.5.5 for `libcrypto-3-x64.dll` and `libssl-3-x64.dll`, and OpenSSL 3.0.16 for `libcrypto-3.dll` and `libssl-3.dll`. Version-matched upstream `LICENSE.txt` and `ACKNOWLEDGEMENTS.md` are staged under `third_party/notices/openssl-3.5.5/` and `third_party/notices/openssl-3.0.16/`. This metadata does not establish the supplying distribution or exact build provenance. The archive includes the Python license; supplier provenance remains an audit limitation.

## Dependency and bundle limits

The project pins `PySide6==6.12.0`. In the inspected environment, PySide6 wheel metadata required Essentials and Addons at 6.12.0, plus `PySide6_WebEngine==6.12.0.140` and `PySide6_Pdf==6.12.0.140`; WebEngine also depends on Addons and PDF on Essentials. The final frozen inventory excludes their binaries, while the build manifest records installed distributions separately from collected files. Pydantic's exact and lower-bounded transitive requirements also mean the resolved versions should be captured for every build.

PatchTrace source imports `PySide6.QtCore`, `QtGui`, and `QtWidgets`; the frozen inventory additionally includes Qt Network through the linked Qt dependency graph. The CI artifact report verifies a Windows onedir ZIP and enumerates the collected files. `--onedir` keeps Qt DLLs as separate files intended to be replaceable; the automated build confirms the layout, but this audit does not include an interactive user replacement test.

## Release follow-up

Before a subsequent release, repeat the ZIP/inventory comparison after any dependency, Qt plugin, or packaging change. Record the supplier/build provenance for the OpenSSL DLLs so the version-resource match can be tied to the included binaries. An interactive check of DLL replacement and the full desktop UI remains distinct from the automated frozen self-test.


## Per-user Windows installer follow-up (2026-10-17)

The Windows CI packaging change adds an Inno Setup per-user wrapper around the already-tested dist/PatchTrace one-folder bundle. The installer requires Windows x64, targets the current user's LocalAppData, adds a Start Menu shortcut, and has no setup-time downloads, administrator requirement, custom actions or runtime prerequisites. The compiler is a CI build dependency, not a user dependency. The installer is unsigned, consistent with SPEC-52. CI verifies install, Qt DLL/plugin presence, the packaged --self-test, and uninstall from a temporary path containing spaces and Unicode. This row records the implemented acceptance gate; pass status is pending the final Windows workflow run on the release branch.
