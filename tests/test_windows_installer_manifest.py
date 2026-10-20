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
    assert '!define REPO_ROOT "${__FILEDIR__}.."' in script
    assert '!include "${REPO_ROOT}\\dist\\PatchTrace-Uninstall.nsh"' in script
    assert 'RMDir /r "$INSTDIR"' not in script
    assert 'Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\PatchTrace' in script


def test_nsis_source_paths_are_anchored_to_repository_root():
    script = (ROOT / "installer" / "PatchTrace.nsi").read_text(encoding="utf-8")
    assert '!insertmacro MUI_PAGE_LICENSE "${REPO_ROOT}\\LICENSE"' in script
    assert 'File /r "${REPO_ROOT}\\dist\\PatchTrace\\*"' in script
    assert 'File "${REPO_ROOT}\\third_party\\notices\\nsis-3.13\\COPYING"' in script
    assert 'OutFile "${REPO_ROOT}\\dist\\PatchTrace-Windows-x64-Setup.exe"' in script
