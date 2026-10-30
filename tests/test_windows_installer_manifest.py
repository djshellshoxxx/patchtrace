"""Regression coverage for Windows installer-owned file cleanup without data loss."""
from __future__ import annotations

import runpy
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELPERS = runpy.run_path(str(ROOT / "tools" / "package_windows_installer.py"))


def test_uninstaller_manifest_removes_only_known_bundle_files(tmp_path: Path):
    bundle = tmp_path / "PatchTrace"
    (bundle / "_internal" / "Qt plugins").mkdir(parents=True)
    (bundle / "PatchTrace.exe").write_bytes(b"exe")
    (bundle / "_internal" / "Qt plugins" / "qwindows.dll").write_bytes(b"dll")
    (bundle / "example$asset.txt").write_text("test", encoding="utf-8")

    manifest = tmp_path / "uninstall.nsh"
    HELPERS["write_uninstall_manifest"](bundle, manifest)
    script = manifest.read_text(encoding="utf-8")

    assert 'Delete "$INSTDIR\\PatchTrace.exe"' in script
    assert 'Delete "$INSTDIR\\_internal\\Qt plugins\\qwindows.dll"' in script
    assert 'Delete "$INSTDIR\\example$$asset.txt"' in script
    assert 'Delete "$INSTDIR\\licenses\\installer\\COPYING"' in script
    assert 'Delete "$INSTDIR\\Uninstall.exe"' in script
    assert 'RMDir "$INSTDIR\\_internal\\Qt plugins"' in script
    assert 'RMDir "$INSTDIR"' in script
    assert "RMDir /r" not in script
    assert "rmdir /S" not in script
    assert script.index('RMDir "$INSTDIR\\_internal\\Qt plugins"') < script.index('RMDir "$INSTDIR\\_internal"')


def test_uninstaller_manifest_rejects_missing_executable(tmp_path: Path):
    bundle = tmp_path / "PatchTrace"
    bundle.mkdir()
    with pytest.raises(FileNotFoundError):
        HELPERS["write_uninstall_manifest"](bundle, tmp_path / "manifest.nsh")


def test_nsis_installer_script_uses_generated_manifest():
    script = (ROOT / "installer" / "PatchTrace.nsi").read_text(encoding="utf-8")
    assert '!define REPO_ROOT "${__FILEDIR__}\\.."' in script
    assert '!include "${REPO_ROOT}\\dist\\PatchTrace-Uninstall.nsh"' in script
    assert 'RMDir /r "$INSTDIR"' not in script
    assert 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PatchTrace' in script


def test_nsis_source_paths_are_anchored_to_repository_root():
    script = (ROOT / "installer" / "PatchTrace.nsi").read_text(encoding="utf-8")
    assert '!insertmacro MUI_PAGE_LICENSE "${REPO_ROOT}\\LICENSE"' in script
    assert 'File /r "${REPO_ROOT}\\dist\\PatchTrace\\*"' in script
    assert 'File "${REPO_ROOT}\\third_party\\notices\\nsis-3.13\\COPYING"' in script
    assert 'OutFile "${REPO_ROOT}\\dist\\PatchTrace-Windows-x64-Setup.exe"' in script


def test_installer_checksum_sidecar_is_lf_only_and_verifiable(tmp_path: Path):
    # Regression: the Setup sidecar was written in text mode, so on Windows it ended in CRLF and
    # `sha256sum -c` failed with "PatchTrace-Windows-x64-Setup.exe\r: No such file" (windows-validate, run 40625345051).
    import hashlib

    installer = tmp_path / "PatchTrace-Windows-x64-Setup.exe"
    installer.write_bytes(b"MZ installer bytes")
    sidecar = HELPERS["write_checksum"](installer)
    expected = f"{hashlib.sha256(b'MZ installer bytes').hexdigest()}  {installer.name}\n".encode("ascii")
    assert sidecar.name == "PatchTrace-Windows-x64-Setup.exe.sha256"
    assert sidecar.read_bytes() == expected and b"\r" not in sidecar.read_bytes()
    source = (ROOT / "tools" / "package_windows_installer.py").read_text(encoding="utf-8")
    assert "write_checksum(installer)" in source and '.sha256")\n    checksum.write_text' not in source
