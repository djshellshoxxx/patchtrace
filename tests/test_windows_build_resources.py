"""SPEC-52 WIN-1 build resources: version resource, .exe icon, application mark and the post-build check.

The Windows build itself only runs on Windows CI; these tests pin everything it consumes on any host, including a
round trip through PyInstaller's own version-resource serializer and PatchTrace's PE reader.
"""
from __future__ import annotations

import importlib
import os
import struct
import sys
from pathlib import Path

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from pe_rsrc_builder import LANG_EN_US, RT_VERSION, rsrc_pe, tree

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))

import build_windows  # noqa: E402
import check_windows_exe  # noqa: E402
import windows_icon  # noqa: E402
import windows_version_info as wvi  # noqa: E402

from patchtrace import app_icon as app_icon_module  # noqa: E402
from patchtrace.app_icon import ICON_SIZES, app_icon, mark_svg, render_image  # noqa: E402

COMMIT = 'e093ade3e66eebf915d1c93c75cf18c033c2abb5'
COPYRIGHT = 'Copyright (c) 2026 Circuit Drift Labs'
PNG = b'\x89PNG\r\n\x1a\n'
RT_GROUP_ICON = 14


# ---- release label (mirrors the release job's tag names) ---------------------------------------------------

@pytest.mark.parametrize('env, label', [
    ({'GITHUB_REF': 'refs/tags/v0.1.0-alpha.1', 'GITHUB_RUN_NUMBER': '7'}, '0.1.0-alpha.1'),
    ({'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'push', 'GITHUB_RUN_NUMBER': '506'}, '0.1.0-beta.506'),
    ({'GITHUB_REF': 'refs/pull/102/merge', 'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_RUN_NUMBER': '9'},
     '0.1.0-dev.9'),
    ({'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch', 'GITHUB_RUN_NUMBER': '9'},
     '0.1.0-dev.9'),
    ({}, '0.1.0-dev'),
])
def test_release_label_follows_the_release_job(env, label):
    assert wvi.release_label('0.1.0', env) == label


@pytest.mark.parametrize('env', [
    {'GITHUB_REF': 'refs/tags/v0.2.0'},  # the tag disagrees with the package version
    {'GITHUB_REF': "refs/tags/v0.1.0-a'b"},  # a quote must never reach the eval()ed file
    {'GITHUB_REF': 'refs/tags/v0.1.0-' + 'x' * 17},
    {'GITHUB_RUN_NUMBER': '65536'},
    {'GITHUB_RUN_NUMBER': '1e3'},
])
def test_release_label_rejects_unsafe_or_mismatched_input(env):
    with pytest.raises(ValueError, match='PT-BUILD'):
        wvi.release_label('0.1.0', env)


@pytest.mark.parametrize('label, commit, build, copyright', [
    ('0.1.0', COMMIT.upper(), 0, COPYRIGHT),
    ('0.1.0', COMMIT[:6], 0, COPYRIGHT),
    ('0.1.0', COMMIT + "'", 0, COPYRIGHT),
    ('0.1.0', COMMIT, 70000, COPYRIGHT),
    ('0.1.0', COMMIT, 0, "Copyright (c) 2026 X'); import os; ('"),
    ('70000.0.0', COMMIT, 0, COPYRIGHT),
])
def test_make_fields_fails_closed(label, commit, build, copyright):
    with pytest.raises(ValueError, match='PT-BUILD'):
        wvi.make_fields(label, commit, build, copyright)


def test_copyright_comes_from_the_license():
    assert wvi.copyright_line((ROOT / 'LICENSE').read_text(encoding='utf-8')) == COPYRIGHT
    with pytest.raises(ValueError):
        wvi.copyright_line('MIT License\n')


def test_version_info_generator_is_deterministic(tmp_path):
    fields = wvi.make_fields('0.1.0-alpha.1', COMMIT, 7, COPYRIGHT)
    first = wvi.write(fields, tmp_path / 'a.txt').read_bytes()
    assert first == wvi.write(fields, tmp_path / 'b.txt').read_bytes()
    assert b'\r\n' not in first and b'CompanyName' not in first
    other = wvi.make_fields('0.1.0-alpha.1', 'f' * 40, 7, COPYRIGHT)
    assert wvi.render(other) != first.decode('utf-8')


def test_fields_for_build_reads_license_and_commit(tmp_path):
    (tmp_path / 'LICENSE').write_text(f'MIT License\n\n{COPYRIGHT}\n', encoding='utf-8')
    env = {'GITHUB_REF': 'refs/tags/v0.1.0-alpha.1', 'GITHUB_SHA': COMMIT, 'GITHUB_RUN_NUMBER': '12'}
    fields = wvi.fields_for_build('0.1.0', env, root=tmp_path)
    assert (fields.label, fields.quad, fields.commit, fields.prerelease) == ('0.1.0-alpha.1', (0, 1, 0, 12), COMMIT,
                                                                              True)
    local = wvi.fields_for_build('0.1.0', {}, root=ROOT)  # falls back to git; a checkout always has a HEAD
    assert wvi.COMMIT_RE.match(local.commit) and local.label == '0.1.0-dev'


# ---- round trip: PyInstaller's serializer, then PatchTrace's own PE reader -----------------------------------

class _WindowsStruct:
    """`struct` with Windows sizes. PyInstaller's serializer packs native '13L'/'HHH' formats, which give the
    RT_VERSION layout only where a C long is 4 bytes (Windows); elsewhere a long is 8 bytes. All its formats are
    single-type, so standard little-endian sizes reproduce the Windows bytes exactly."""

    @staticmethod
    def pack(fmt, *values):
        return struct.pack('<' + fmt, *values)

    @staticmethod
    def unpack(fmt, data):
        return struct.unpack('<' + fmt, data)


def _pyinstaller_versioninfo(monkeypatch):
    """PyInstaller's version-file loader and serializer. Only its .exe *reader* needs win32api, absent off Windows."""
    import PyInstaller.compat as compat

    if not hasattr(compat, 'win32api'):
        monkeypatch.setattr(compat, 'win32api', None, raising=False)
    monkeypatch.delitem(sys.modules, 'PyInstaller.utils.win32.versioninfo', raising=False)
    module = importlib.import_module('PyInstaller.utils.win32.versioninfo')
    if struct.calcsize('L') != 4:
        monkeypatch.setattr(module, 'struct', _WindowsStruct)
    return module


def _exe(tmp_path, resources):
    data, _info = rsrc_pe(tree(resources))
    path = tmp_path / 'PatchTrace.exe'
    path.write_bytes(data)
    return path


def test_generated_file_is_what_pyinstaller_embeds_and_patchtrace_reads_it_back(tmp_path, monkeypatch):
    versioninfo = _pyinstaller_versioninfo(monkeypatch)
    fields = wvi.make_fields('0.1.0-alpha.1', COMMIT, 7, COPYRIGHT)
    info = versioninfo.load_version_info_from_text_file(str(wvi.write(fields, tmp_path / 'version-info.txt')))
    raw = bytes(info.toRaw())  # the RT_VERSION bytes PyInstaller writes into the executable
    assert info.ffi.fileFlags & wvi.VS_FF_PRERELEASE

    without_icon = check_windows_exe.read_resources(_exe(tmp_path, {RT_VERSION: {1: {LANG_EN_US: raw}}}))
    assert without_icon['file_version'] == '0.1.0.7'
    assert without_icon['strings'] == fields.strings()
    assert check_windows_exe.problems(without_icon, fields.label, COMMIT) == ['PT-REL-ICON: no RT_GROUP_ICON resource']

    group = struct.pack('<HHH', 0, 1, 0)
    found = check_windows_exe.read_resources(
        _exe(tmp_path, {RT_VERSION: {1: {LANG_EN_US: raw}}, RT_GROUP_ICON: {1: {LANG_EN_US: group}}}))
    assert found['icon_groups'] == 1
    assert check_windows_exe.problems(found, fields.label, COMMIT) == []
    assert check_windows_exe.problems(found, '0.1.0-alpha.2', COMMIT)  # a stale label is caught
    assert check_windows_exe.problems(found, fields.label, 'f' * 40)  # so is the wrong commit


def test_check_rejects_a_publisher_name_and_a_missing_version_resource(tmp_path):
    strings = {**wvi.make_fields('0.1.0', COMMIT, 0, COPYRIGHT).strings(), 'CompanyName': 'Someone'}
    found = {'status': 'ok', 'strings': strings, 'file_version': '0.1.0.0', 'icon_groups': 1}
    assert check_windows_exe.problems(found, '0.1.0', COMMIT) == [
        'PT-REL-PUBLISHER: unsigned builds must not carry a CompanyName (SPEC-52)']
    bare = check_windows_exe.read_resources(_exe(tmp_path, {RT_GROUP_ICON: {1: {LANG_EN_US: b'\0' * 6}}}))
    assert bare['strings'] == {} and len(check_windows_exe.problems(bare, '0.1.0', COMMIT)) == 4


# ---- .ico packing -------------------------------------------------------------------------------------------

def test_pack_ico_layout():
    small, large = PNG + b'small', PNG + b'large-frame'
    data = windows_icon.pack_ico([(16, small), (256, large)])
    assert struct.unpack_from('<HHH', data) == (0, 1, 2)
    first = struct.unpack_from('<BBBBHHII', data, 6)
    second = struct.unpack_from('<BBBBHHII', data, 22)
    assert first == (16, 16, 0, 0, 1, 32, len(small), 38)
    assert second == (0, 0, 0, 0, 1, 32, len(large), 38 + len(small))  # 0 encodes 256
    assert data[38:38 + len(small)] == small and data[38 + len(small):] == large


@pytest.mark.parametrize('frames', [[], [(16, b'not a png')], [(0, PNG)], [(257, PNG)], [(16, PNG), (16, PNG)],
                                    [(n, PNG) for n in range(1, 18)], [(16, PNG + b'\0' * (1 << 20))]])
def test_pack_ico_rejects_bad_frames(frames):
    with pytest.raises(ValueError):
        windows_icon.pack_ico(frames)


# ---- the mark and its rendering (Qt offscreen) ----------------------------------------------------------------

def test_packaged_mark_is_the_site_mark():
    assert (ROOT / 'src/patchtrace/resources/patchtrace-mark.svg').read_bytes() == \
        (ROOT / 'site/assets/cdl-mark.svg').read_bytes()
    assert mark_svg().startswith(b'<svg')


def test_hook_ships_the_mark_with_the_frozen_package():
    hook = (ROOT / 'tools/pyinstaller_hooks/hook-patchtrace.app_icon.py').read_text(encoding='utf-8')
    assert "datas = [(str(_MARK), 'patchtrace/resources')]" in hook


def test_icon_frames_render_and_qt_reads_the_ico_back(qapp):
    from PySide6.QtCore import QBuffer, QByteArray, QIODevice
    from PySide6.QtGui import QImage, QImageReader

    frames = windows_icon.render_frames()
    assert [size for size, _png in frames] == list(ICON_SIZES)
    for size, png in frames:
        image = QImage.fromData(png, 'PNG')
        assert (image.width(), image.height()) == (size, size)
    big = QImage.fromData(frames[-1][1], 'PNG')
    assert big.pixelColor(128, 128).alpha() == 255  # the mark fills its square: not a blank render
    data = QByteArray(windows_icon.pack_ico(frames))  # keep a reference: QBuffer does not own its QByteArray
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.ReadOnly)
    reader = QImageReader(buffer, b'ico')
    assert reader.imageCount() == len(frames)


def test_app_icon_has_every_size_and_is_empty_not_fatal_without_the_mark(qapp, monkeypatch):
    icon = app_icon()
    assert not icon.isNull()
    assert sorted(size.width() for size in icon.availableSizes()) == list(ICON_SIZES)

    def gone():
        raise OSError('resource missing')
    monkeypatch.setattr(app_icon_module, 'mark_svg', gone)
    assert app_icon().isNull()


def test_render_rejects_invalid_svg_and_sizes(qapp):
    with pytest.raises(ValueError, match='PT-ICON'):
        render_image(b'<svg', 16)
    for size in (0, 257):
        with pytest.raises(ValueError, match='PT-ICON'):
            render_image(mark_svg(), size)


# ---- the build command --------------------------------------------------------------------------------------

def test_pyinstaller_command_embeds_icon_and_version_resource(tmp_path):
    icon, version_file = tmp_path / 'PatchTrace.ico', tmp_path / 'version-info.txt'
    command = build_windows.pyinstaller_command(ROOT, icon, version_file)
    assert command[command.index('--icon') + 1] == str(icon)
    assert command[command.index('--version-file') + 1] == str(version_file)
    assert command[command.index('--hide-console') + 1] == 'hide-early'
    assert {'--onedir', '--console'} <= set(command) and '--manifest' not in command
