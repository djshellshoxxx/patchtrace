"""QA-FUZZ: hostile offline ZIP bundles (traversal, symlinks, reserved names, duplicates, bombs, byte corruption).

Properties: every hostile archive is refused with OfflineBundleError before any extraction; accepted member names
follow the portable rules checked by an independent oracle; a corrupted archive never raises anything else. The
bundles are built in temporary directories and are only parsed, never extracted or executed.
"""
from __future__ import annotations

import stat
import tempfile
import warnings
import zipfile
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from patchtrace.offline_bundle import (
    WINDOWS_RESERVED,
    OfflineBundleError,
    _safe_relative,
    build_offline_bundle,
    inspect_offline_bundle,
)

LINUX = ('linux',)
REGULAR = (stat.S_IFREG | 0o644) << 16
SYMLINK = (stat.S_IFLNK | 0o777) << 16
DIRECTORY = (stat.S_IFDIR | 0o755) << 16
PAYLOAD = {
    'python/bin/python3': b'stub-interpreter\n',
    'ghidra/Ghidra/application.properties': b'version=stub\n',
    'jdk/bin/java': b'stub-java\n',
    'LICENSES/NOTICE.txt': b'notice\n',
    'docs/café.txt': b'nfc name\n',
}
VERSIONS = {'python': '3.12.0', 'ghidra': '11.0', 'jdk': '21', 'ghidriff_revision': 'r1'}
SETTINGS = settings(max_examples=120, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
COMPONENT = st.one_of(st.text(alphabet=list('abCONaux.:\\ /<>|?*\x00\x7fé¹$'), max_size=9),
                      st.sampled_from(['AUX', 'nul', 'COM¹', 'lpt3.txt', 'con ', 'CON.x', 'Nul.']))


def _base_bundle(root: Path, payload: dict[str, bytes] | None = None) -> Path:
    source = root / 'source'
    for name, data in (payload or PAYLOAD).items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    destination = root / 'bundle.zip'
    build_offline_bundle(source, 'qa-fuzz-runtime', VERSIONS, destination, platform='linux')
    return destination


def _members(archive: Path) -> list[tuple[str, bytes, int]]:
    with zipfile.ZipFile(archive) as zf:
        return [(info.filename, zf.read(info), info.external_attr) for info in zf.infolist()]


def _write_zip(path: Path, members: list[tuple[str, bytes, int]]) -> Path:
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')  # duplicate names are the input under test, not a mistake
        with zipfile.ZipFile(path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for name, data, attr in members:
                info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = attr
                zf.writestr(info, data)
    return path


def _payload_name(members, name):
    return next(i for i, (n, _, _) in enumerate(members) if n == name)


# --- portable member names (oracle-checked) ----------------------------------------------------------------------

@SETTINGS
@given(st.lists(COMPONENT, min_size=1, max_size=4))
def test_safe_relative_accepts_only_names_that_pass_the_portable_oracle(parts):
    name = '/'.join(parts)
    try:
        accepted = _safe_relative(name)
    except OfflineBundleError:
        return
    assert accepted == name
    assert '\\' not in accepted and not accepted.startswith('/')
    for part in accepted.split('/'):
        assert part not in ('', '.', '..')
        assert not part.endswith((' ', '.'))
        assert not set(part) & set('<>"|?*:')
        assert all(ord(c) >= 32 and ord(c) != 127 for c in part)
        assert part.split('.')[0].rstrip(' ').upper() not in WINDOWS_RESERVED


@pytest.mark.parametrize('name', ['payload/CON', 'payload/aux.txt', 'nul', 'COM¹/x', 'LPT3.log', 'CONIN$',
                                  'payload/trailing.', 'payload/space ', 'a:stream', 'a\\b', '../escape', '/abs',
                                  'a//b', 'x/./y', 'bell\x07'],
                         ids=['con', 'aux-ext', 'nul', 'com1-superscript', 'lpt3-ext', 'conin', 'trailing-dot',
                              'trailing-space', 'ads-colon', 'backslash', 'traversal', 'absolute', 'double-slash',
                              'dot-part', 'control'])
def test_known_hostile_names_are_refused(name):
    with pytest.raises(OfflineBundleError):
        _safe_relative(name)


# --- hostile archives built from a valid bundle --------------------------------------------------------------------

def _hostile_variants(members):
    payload = next(n for n, _, _ in members if n.startswith('payload/'))
    nfd = 'payload/docs/café.txt'
    notice = next(i for i, (n, _, _) in enumerate(members) if n == 'payload/LICENSES/NOTICE.txt')
    return {
        'traversal-member': members + [('../escape.txt', b'x', REGULAR)],
        'absolute-member': members + [('/payload/x', b'x', REGULAR)],
        'backslash-name': [(n.replace('payload/jdk', 'payload\\jdk'), d, a) for n, d, a in members],
        'symlink-payload': [(n, b'/etc/passwd', SYMLINK) if n == payload else (n, d, a)
                            for n, d, a in members],
        'directory-entry': members + [('payload/', b'', DIRECTORY)],
        'exact-duplicate': members + [members[_payload_name(members, payload)]],
        'case-collision-manifest': members + [('MANIFEST.JSON', b'{}', REGULAR)],
        'case-collision-notice': members + [('payload/licenses/notice.txt', b'x', REGULAR)],
        'nfd-collision': members + [(nfd, b'nfd', REGULAR)],
        'reserved-member': members + [('payload/CON', b'x', REGULAR)],
        'reserved-com1-superscript': members + [('payload/COM¹.txt', b'x', REGULAR)],
        'extra-unlisted-file': members + [('payload/extra.bin', b'x', REGULAR)],
        'notice-dropped': [m for i, m in enumerate(members) if i != notice],
    }


@pytest.mark.parametrize('variant', ['traversal-member', 'absolute-member', 'backslash-name', 'symlink-payload',
                                     'directory-entry', 'exact-duplicate', 'case-collision-manifest',
                                     'case-collision-notice', 'nfd-collision', 'reserved-member',
                                     'reserved-com1-superscript', 'extra-unlisted-file', 'notice-dropped'])
def test_hostile_member_layout_is_refused_before_extraction(tmp_path, variant):
    base = _base_bundle(tmp_path)
    assert inspect_offline_bundle(base, platforms=LINUX).runtime_id == 'qa-fuzz-runtime'
    hostile = _write_zip(tmp_path / 'hostile.zip', _hostile_variants(_members(base))[variant])
    with pytest.raises(OfflineBundleError):
        inspect_offline_bundle(hostile, platforms=LINUX)
    assert not (tmp_path / 'escape.txt').exists()


def test_compression_bomb_member_is_refused(tmp_path):
    # The producer refuses to build such a member, so the hostile archive is assembled by hand.
    base = _base_bundle(tmp_path)
    zeros = bytes(4 * 1024 * 1024)
    bomb = _write_zip(tmp_path / 'bomb.zip', _members(base) + [('payload/data/zeros.bin', zeros, REGULAR)])
    with pytest.raises(OfflineBundleError) as info:
        inspect_offline_bundle(bomb, platforms=LINUX)
    assert 'compression limits' in str(info.value)


def test_invalid_utf8_member_name_is_a_typed_offline_error(tmp_path):
    base = _base_bundle(tmp_path)
    raw = base.read_bytes()
    assert raw.count(b'caf\xc3\xa9') == 2  # local header and central directory both carry the UTF-8 name
    corrupt = tmp_path / 'utf8.zip'
    corrupt.write_bytes(raw.replace(b'caf\xc3\xa9', b'caf\xc3\x28'))
    with pytest.raises(OfflineBundleError):
        inspect_offline_bundle(corrupt, platforms=LINUX)


def test_bzip2_member_is_refused_as_unsupported_compression(tmp_path):
    base = _base_bundle(tmp_path)
    with zipfile.ZipFile(base) as zf:
        members = [(i.filename, zf.read(i), i.external_attr) for i in zf.infolist()]
    hostile = tmp_path / 'bzip2.zip'
    with zipfile.ZipFile(hostile, 'w') as zf:
        for name, data, attr in members:
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_BZIP2
            info.external_attr = attr
            zf.writestr(info, data)
    with pytest.raises(OfflineBundleError):
        inspect_offline_bundle(hostile, platforms=LINUX)


@SETTINGS
@given(st.lists(st.tuples(st.integers(0, 4095), st.integers(0, 255)), min_size=1, max_size=3))
def test_corrupted_bundle_bytes_only_raise_offline_error(flips):
    with tempfile.TemporaryDirectory() as root:
        base = _base_bundle(Path(root))
        raw = bytearray(base.read_bytes())
        for offset, value in flips:
            raw[offset % len(raw)] = value
        corrupt = Path(root) / 'corrupt.zip'
        corrupt.write_bytes(bytes(raw))
        try:
            inspect_offline_bundle(corrupt, platforms=LINUX)
        except OfflineBundleError:
            pass


@SETTINGS
@given(st.integers(0, 2 ** 16))
def test_truncated_bundles_only_raise_offline_error(cut):
    with tempfile.TemporaryDirectory() as root:
        base = _base_bundle(Path(root))
        raw = base.read_bytes()
        short = Path(root) / 'short.zip'
        short.write_bytes(raw[:cut % len(raw)])
        with pytest.raises(OfflineBundleError):
            inspect_offline_bundle(short, platforms=LINUX)
