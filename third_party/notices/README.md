# Upstream notice source inventory

These files are verbatim license texts from upstream source revisions. They are references for the Windows distribution notice bundle; they do not determine which license applies to each collected binary. Keep the exact dependency inventory and the final frozen-package file list with each release.

## PySide and Shiboken

- Upstream repository: [pyside-setup](https://code.qt.io/cgit/pyside/pyside-setup.git/)
- Release tag: `v6.12.0`
- Peeled commit: `f50facb83fc3dc5f3240c854668c7a6dd93871b2`
- `LICENSES/` contains the release's license texts, including LGPL-3.0-only, GPL-2.0-only, GPL-3.0-only, the Qt GPL exception, and listed third-party license texts.
- `sources/PySide6-licensecomment.txt`, `sources/PySide6-COPYING-LGPL-2.1.txt`, `sources/Shiboken-COPYING-GPL-2.0.txt`, and `sources/libshiboken-COPYING-LGPL-2.1.txt` preserve source-level notices found in the same tag. They are retained as upstream records; this inventory does not resolve which notice governs each generated wheel component.
- Wheel metadata in the inspected build environment reported `LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only` for PySide6, Essentials, Addons, and shiboken6. The wheel files did not expose matching license texts in their package file lists, which is why source copies are maintained here.

## Qt 6.12.0

- Upstream repository: [qtbase](https://code.qt.io/cgit/qt/qtbase.git/)
- Release tag: `v6.12.0`
- Peeled commit: `025bdad181de241e81bf853c8a2d7bf3d19261a9`
- `LICENSES/` contains the standard license texts present in that exact qtbase release, including the Qt GPL exception and the common third-party license texts referenced by Qt modules.
- `attributions/` contains the official Qt 6.12 Core and GUI attribution pages linked by Qt's [Qt 6.12 third-party code index](https://doc.qt.io/qt-6.12/licenses-used-in-qt.html), plus a local index of their component names and license identifiers. This preserves the upstream attributions rather than only generic license texts. The pages cover module source, including platform-specific entries; the exact Windows DLL/plugin set has not been inspected, so they are not a claim that every listed component is included in PatchTrace.
- The index is useful to resolve a package-level bill of materials against the Qt modules and plugins actually collected. If the frozen build includes Qt PDF or Qt WebEngine binaries, follow their module entries and obtain any component-specific notices from the corresponding exact upstream sources before release.

## PyInstaller

- Upstream repository: [PyInstaller](https://github.com/pyinstaller/pyinstaller)
- Release tag: `v6.22.3`
- Commit: `ecd7993d65c43b254f4e3f718e36d5b4a70a3ed5`
- `pyinstaller-6.22.3/COPYING.txt` is the exact `COPYING.txt` from that tag (SHA-256 `0598064c7d2718e38d7914a7d08343b2fa008e3bea9ebba2aa7a6ffa5900dd64`); it matches the installed `pyinstaller-6.22.3.dist-info/licenses/COPYING.txt` inspected for this audit. The upstream file describes PyInstaller's GPL license and bootloader exception.

## Scope

These are upstream license texts and source references, not a complete SBOM or final package audit. PySide6 6.12.0 metadata in the inspected environment also required `PySide6_WebEngine==6.12.0.140` and `PySide6_Pdf==6.12.0.140`; the PatchTrace source imports QtCore, QtGui, and QtWidgets, but the Windows PyInstaller collection is the deciding evidence for which binaries ship. Reconcile the actual frozen files, their DLL dependencies, plugins, and distribution metadata before deciding whether additional third-party notices are needed.
