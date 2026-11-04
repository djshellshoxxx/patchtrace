"""tools/verify_release.py: offline verification of a published prerelease (windows-acceptance spec section 1.3,
docs/release-process.md "Verify assets before announcing").

Hermetic: every release, archive, sidecar and ls-remote listing is synthetic and built in tmp_path. Nothing here
contacts GitHub or proves anything about a real release."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import re
import sys
import tarfile
import zipfile
from collections.abc import Callable
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'verify_release.py'
spec = importlib.util.spec_from_file_location('verify_release', TOOL)
vr = importlib.util.module_from_spec(spec)
sys.modules['verify_release'] = vr
spec.loader.exec_module(vr)

TAG = 'v0.1.0-beta.751'
SHA = 'a' * 40
OTHER = 'b' * 40
TAG_OBJECT = 'c' * 40
WINDOWS_ZIP = 'PatchTrace-0.1.0-windows-x64.zip'
PORTABLE = 'PatchTrace-Windows-x64-Portable.zip'
SETUP = 'PatchTrace-Windows-x64-Setup.exe'
LINUX_TAR = 'PatchTrace-0.1.0-linux-x86_64.tar.gz'
PAYLOADS = (WINDOWS_ZIP, PORTABLE, SETUP, LINUX_TAR)


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def versions(commit: str = SHA, label: str = TAG[1:]) -> bytes:
    return json.dumps({'Python': '3.12.10', 'PatchTrace': label, 'PatchTrace commit': commit}, indent=2).encode()


def zip_bytes(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def windows_members(**changes: bytes | None) -> dict[str, bytes]:
    members = {'PatchTrace/PatchTrace.exe': b'MZ frozen', 'PatchTrace/file-inventory.json': b'["PatchTrace.exe"]',
               'PatchTrace/dependency-versions.json': versions()}
    for name, data in changes.items():
        if data is None:
            members.pop(name, None)
        else:
            members[name] = data
    return members


def tar_bytes(members: list[tuple[str, bytes, int]], links: tuple[tuple[str, str], ...] = ()) -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w:gz', format=tarfile.PAX_FORMAT) as archive:
        directory = tarfile.TarInfo('PatchTrace')
        directory.type, directory.mode = tarfile.DIRTYPE, 0o755
        archive.addfile(directory)
        for name, data, mode in members:
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), mode
            archive.addfile(info, io.BytesIO(data))
        for name, target in links:
            info = tarfile.TarInfo(name)
            info.type, info.linkname = tarfile.SYMTYPE, target
            archive.addfile(info)
    return buffer.getvalue()


LINUX_MEMBERS = [('PatchTrace/PatchTrace', b'\x7fELF frozen', 0o755),
                 ('PatchTrace/dependency-versions.json',
                  json.dumps({'Python': '3.12.10', 'platform': 'linux-x86_64'}).encode(), 0o644)]


class Release:
    """A downloaded release directory, its `gh release view --json` document, the ls-remote listing and notes."""

    def __init__(self, root: Path) -> None:
        self.dir = root / 'download'
        self.dir.mkdir()
        self.json_path = root / 'release.json'
        self.peeled_path = root / 'peeled.txt'
        self.notes_path = root / 'notes.md'
        self.record_path = root / 'record.md'
        windows = zip_bytes(windows_members())
        self.files = {WINDOWS_ZIP: windows, PORTABLE: windows, SETUP: b'MZ installer bytes',
                      LINUX_TAR: tar_bytes(LINUX_MEMBERS)}
        self.meta = {'tagName': TAG, 'isPrerelease': True, 'isDraft': False, 'targetCommitish': SHA}
        self.peeled = f'{TAG_OBJECT}\trefs/tags/{TAG}\n{SHA}\trefs/tags/{TAG}^{{}}\n'
        self.notes: str | None = None

    def sidecar(self, name: str) -> bytes:
        return f'{digest(self.files[name])}  {name}\n'.encode('ascii')

    def write(self) -> Release:
        """Payloads, sidecars, then the release JSON describing exactly what is on disk."""
        for name, data in self.files.items():
            (self.dir / name).write_bytes(data)
            (self.dir / f'{name}.sha256').write_bytes(self.sidecar(name))
        self.describe()
        self.peeled_path.write_text(self.peeled, encoding='utf-8', newline='\n')
        return self

    def describe(self, drop: tuple[str, ...] = ()) -> None:
        assets = [{'name': path.name, 'size': path.stat().st_size, 'contentType': 'application/octet-stream',
                   'digest': f'sha256:{digest(path.read_bytes())}', 'state': 'uploaded'}
                  for path in sorted(self.dir.iterdir()) if path.name not in drop]
        body = self.notes if self.notes is not None else notes_for(self.dir)
        document = {**self.meta, 'assets': assets, 'body': body}
        self.json_path.write_text(json.dumps(document, indent=2), encoding='utf-8', newline='\n')

    def argv(self, *extra: str) -> list[str]:
        return ['--tag', TAG, '--sha', SHA, '--release-json', str(self.json_path), '--peeled',
                str(self.peeled_path), '--dir', str(self.dir), *extra]


def notes_for(directory: Path) -> str:
    """The asset lines tools/milestone_notes.py prints (ZIP and tar.gz only)."""
    lines = ['## PatchTrace beta', '', f'Commit: {SHA} (main)', 'Assets:']
    for name in (WINDOWS_ZIP, LINUX_TAR):
        data = (directory / name).read_bytes()
        lines.append(f'- {name} - {len(data)} bytes - SHA-256 {digest(data)}')
    lines.append('Verify: `sha256sum -c <file>.sha256`.')
    return '\n'.join(lines) + '\n'


def run(release: Release, *extra: str) -> tuple[int, dict, str]:
    out, err = io.StringIO(), io.StringIO()
    code = vr.main(release.argv('--json', *extra), out=out, err=err)
    document = json.loads(out.getvalue()) if out.getvalue() else {}
    return code, document, err.getvalue()


def by_id(document: dict) -> dict[str, dict]:
    return {check['id']: check for check in document['checks']}


def failures(document: dict) -> dict[str, str]:
    return {check['id']: check['code'] for check in document['checks'] if check['status'] == 'fail'}


@pytest.fixture
def release(tmp_path: Path) -> Release:
    return Release(tmp_path)


# ---------------------------------------------------------------- the good release

def test_a_consistent_release_passes_and_the_linux_commit_stays_not_checked(release):
    code, document, err = run(release.write())
    assert code == 0, err
    checks = by_id(document)
    assert failures(document) == {}
    assert checks['commit:linux-tar']['status'] == 'not-checked'
    assert 'records no commit' in checks['commit:linux-tar']['detail']
    assert {check['status'] for check in document['checks']} == {'pass', 'not-checked'}
    assert [check_id for check_id, check in checks.items() if check['status'] == 'not-checked'] == [
        'commit:linux-tar']
    for name in PAYLOADS:
        assert checks[f'asset:{name}']['status'] == 'pass'
        assert checks[f'asset:{name}.sha256']['status'] == 'pass'
        assert checks[f'sidecar:{name}.sha256']['status'] == 'pass'
        assert checks[f'hash:{name}']['status'] == 'pass'
    for check_id in ('tag', 'prerelease', 'commit:target', 'commit:peeled', 'commit:windows-zip', 'portable',
                     'archive:windows-zip', 'archive:linux-tar'):
        assert checks[check_id]['status'] == 'pass', checks[check_id]
    assert document['result'] == 'pass' and document['tag'] == TAG and document['sha'] == SHA
    assert all(check['code'] is None for check in document['checks'])


def test_every_check_has_the_four_fields_and_a_bounded_one_line_detail(release):
    _, document, _ = run(release.write())
    for check in document['checks']:
        assert set(check) == {'id', 'status', 'code', 'detail'}
        assert '\n' not in check['detail'] and len(check['detail']) <= vr.DETAIL_LIMIT


def test_a_lightweight_tag_uses_the_plain_ref(release):
    release.peeled = f'{SHA}\trefs/tags/{TAG}\n'
    code, document, _ = run(release.write())
    assert code == 0 and by_id(document)['commit:peeled']['status'] == 'pass'


def test_the_human_report_lists_each_check_on_one_line(release):
    out, err = io.StringIO(), io.StringIO()
    assert vr.main(release.write().argv(), out=out, err=err) == 0
    lines = out.getvalue().splitlines()
    assert any(line.startswith('pass') and 'commit:peeled' in line for line in lines)
    assert any(line.startswith('not-checked') and 'commit:linux-tar' in line for line in lines)
    assert lines[-1].startswith('result=pass')


# ---------------------------------------------------------------- each defect fails with its code

def crlf_sidecar(release: Release) -> None:
    path = release.dir / f'{SETUP}.sha256'
    path.write_bytes(release.sidecar(SETUP).replace(b'\n', b'\r\n'))
    release.describe()


def tampered_byte(release: Release) -> None:
    path = release.dir / SETUP
    data = bytearray(path.read_bytes())
    data[3] ^= 0x01
    path.write_bytes(bytes(data))


def portable_differs(release: Release) -> None:
    other = zip_bytes(windows_members(**{'PatchTrace/README.md': b'extra'}))
    release.files[PORTABLE] = other
    (release.dir / PORTABLE).write_bytes(other)
    (release.dir / f'{PORTABLE}.sha256').write_bytes(release.sidecar(PORTABLE))
    release.describe()


def missing_setup_sidecar(release: Release) -> None:
    (release.dir / f'{SETUP}.sha256').unlink()
    release.describe()


def size_differs(release: Release) -> None:
    document = json.loads(release.json_path.read_text(encoding='utf-8'))
    for asset in document['assets']:
        if asset['name'] == LINUX_TAR:
            asset['size'] += 1
    release.json_path.write_text(json.dumps(document), encoding='utf-8', newline='\n')


def meta(**changes: object) -> Callable[[Release], None]:
    def change(release: Release) -> None:
        release.meta.update(changes)
        release.describe()
    return change


def peeled_differs(release: Release) -> None:
    release.peeled_path.write_text(f'{TAG_OBJECT}\trefs/tags/{TAG}\n{OTHER}\trefs/tags/{TAG}^{{}}\n',
                                   encoding='utf-8', newline='\n')


def tag_absent(release: Release) -> None:
    release.peeled_path.write_text(f'{SHA}\trefs/tags/v0.1.0-beta.750\n', encoding='utf-8', newline='\n')


def windows_zip(**changes: bytes | None) -> Callable[[Release], None]:
    def change(release: Release) -> None:
        data = zip_bytes(windows_members(**changes))
        release.files[WINDOWS_ZIP] = release.files[PORTABLE] = data
        release.write()
    return change


def linux_tar(members: list[tuple[str, bytes, int]], links: tuple[tuple[str, str], ...] = ()) -> Callable:
    def change(release: Release) -> None:
        release.files[LINUX_TAR] = tar_bytes(members, links)
        release.write()
    return change


def notes_hash_wrong(release: Release) -> None:
    text = notes_for(release.dir).replace(digest(release.files[LINUX_TAR]), 'f' * 64)
    release.notes_path.write_text(text, encoding='utf-8', newline='\n')


def body_hash_wrong(release: Release) -> None:
    release.notes = notes_for(release.dir).replace(digest(release.files[WINDOWS_ZIP]), '0' * 64)
    release.describe()


def digest_wrong(release: Release) -> None:
    document = json.loads(release.json_path.read_text(encoding='utf-8'))
    for asset in document['assets']:
        if asset['name'] == SETUP:
            asset['digest'] = 'sha256:' + 'e' * 64
    release.json_path.write_text(json.dumps(document), encoding='utf-8', newline='\n')


def sidecar_names_other_file(release: Release) -> None:
    (release.dir / f'{SETUP}.sha256').write_bytes(f'{digest(release.files[SETUP])}  other.exe\n'.encode())
    release.describe()


LINUX_NOEXEC = [('PatchTrace/PatchTrace', b'\x7fELF frozen', 0o644), LINUX_MEMBERS[1]]
DEFECTS = {
    'crlf-sidecar': (crlf_sidecar, {f'sidecar:{SETUP}.sha256': 'PT-REL-SIDECAR-FORMAT'}),
    'sidecar-name': (sidecar_names_other_file, {f'sidecar:{SETUP}.sha256': 'PT-REL-SIDECAR-FORMAT'}),
    'tampered-byte': (tampered_byte, {f'hash:{SETUP}': 'PT-REL-HASH-MISMATCH'}),
    'portable-differs': (portable_differs, {'portable': 'PT-REL-HASH-MISMATCH'}),
    'no-setup-sidecar': (missing_setup_sidecar, {f'asset:{SETUP}.sha256': 'PT-REL-ASSET-MISSING'}),
    'size-differs': (size_differs, {f'asset:{LINUX_TAR}': 'PT-REL-ASSET-MISSING'}),
    'target-main': (meta(targetCommitish='main'), {'commit:target': 'PT-REL-COMMIT-MISMATCH'}),
    'peeled-differs': (peeled_differs, {'commit:peeled': 'PT-REL-COMMIT-MISMATCH'}),
    'tag-absent': (tag_absent, {'commit:peeled': 'PT-REL-COMMIT-MISMATCH'}),
    'not-prerelease': (meta(isPrerelease=False), {'prerelease': 'PT-REL-NOT-PRERELEASE'}),
    'draft': (meta(isDraft=True), {'prerelease': 'PT-REL-NOT-PRERELEASE'}),
    'tag-name': (meta(tagName='v0.1.0-beta.750'), {'tag': 'PT-REL-TAG-MISMATCH'}),
    'dep-commit': (windows_zip(**{'PatchTrace/dependency-versions.json': versions(commit=OTHER)}),
                   {'commit:windows-zip': 'PT-REL-COMMIT-MISMATCH'}),
    'dep-label': (windows_zip(**{'PatchTrace/dependency-versions.json': versions(label='0.1.0-beta.750')}),
                  {'commit:windows-zip': 'PT-REL-COMMIT-MISMATCH'}),
    'dotdot-member': (windows_zip(**{'../x': b'escape'}), {'archive:windows-zip': 'PT-REL-ARCHIVE-CONTENT'}),
    'abs-member': (windows_zip(**{'/etc/x': b'escape'}), {'archive:windows-zip': 'PT-REL-ARCHIVE-CONTENT'}),
    'no-exe': (windows_zip(**{'PatchTrace/PatchTrace.exe': None}), {'archive:windows-zip': 'PT-REL-ARCHIVE-CONTENT'}),
    'no-depvers': (windows_zip(**{'PatchTrace/dependency-versions.json': None}),
                   {'archive:windows-zip': 'PT-REL-ARCHIVE-CONTENT',
                    'commit:windows-zip': 'PT-REL-COMMIT-MISMATCH'}),
    'linux-noexec': (linux_tar(LINUX_NOEXEC), {'archive:linux-tar': 'PT-REL-ARCHIVE-CONTENT'}),
    'linux-dotdot': (linux_tar([*LINUX_MEMBERS, ('PatchTrace/../x', b'escape', 0o644)]),
                     {'archive:linux-tar': 'PT-REL-ARCHIVE-CONTENT'}),
    'linux-link-out': (linux_tar(LINUX_MEMBERS, (('PatchTrace/lib', '../../etc'),)),
                       {'archive:linux-tar': 'PT-REL-ARCHIVE-CONTENT'}),
    'notes-hash': (notes_hash_wrong, {f'hash:{LINUX_TAR}': 'PT-REL-HASH-MISMATCH'}),
    'body-hash': (body_hash_wrong, {f'hash:{WINDOWS_ZIP}': 'PT-REL-HASH-MISMATCH'}),
    'digest-wrong': (digest_wrong, {f'hash:{SETUP}': 'PT-REL-HASH-MISMATCH'}),
}


@pytest.mark.parametrize('defect', list(DEFECTS), ids=list(DEFECTS))
def test_each_defect_fails_with_its_code_and_exit_3(release, defect):
    change, expected = DEFECTS[defect]
    release.write()
    change(release)
    extra = ('--notes', str(release.notes_path)) if release.notes_path.exists() else ()
    code, document, _ = run(release, *extra)
    assert code == 3
    assert failures(document) == expected
    assert document['result'] == 'fail'


def test_a_crlf_sidecar_still_compares_its_hash(release):
    release.write()
    crlf_sidecar(release)
    _, document, _ = run(release)
    assert by_id(document)[f'hash:{SETUP}']['status'] == 'pass'


def test_a_missing_payload_is_not_checked_downstream_but_fails_its_asset(release):
    release.write()
    (release.dir / SETUP).unlink()
    release.describe()
    code, document, _ = run(release)
    checks = by_id(document)
    assert code == 3 and failures(document) == {f'asset:{SETUP}': 'PT-REL-ASSET-MISSING'}
    assert checks[f'hash:{SETUP}']['status'] == 'not-checked'


def test_an_asset_listed_but_not_downloaded_fails(release):
    release.write()
    (release.dir / f'{LINUX_TAR}.sha256').unlink()
    code, document, _ = run(release)
    assert code == 3 and failures(document)[f'asset:{LINUX_TAR}.sha256'] == 'PT-REL-ASSET-MISSING'


def test_notes_that_print_no_hash_are_named_in_the_detail(release):
    release.notes = 'Static preamble only.\n'
    release.write()
    code, document, _ = run(release)
    assert code == 0
    assert 'notes print no hash' in by_id(document)[f'hash:{WINDOWS_ZIP}']['detail']


def test_a_notes_line_for_the_sidecar_does_not_count_for_the_zip(release):
    release.write()
    text = notes_for(release.dir) + f'- {WINDOWS_ZIP}.sha256 - SHA-256 {"9" * 64}\n'
    release.notes_path.write_text(text, encoding='utf-8', newline='\n')
    code, document, _ = run(release, '--notes', str(release.notes_path))
    assert failures(document) == {f'hash:{WINDOWS_ZIP}.sha256': 'PT-REL-HASH-MISMATCH'} and code == 3


def test_a_duplicate_dependency_versions_member_fails_the_zip(release):
    # The later, matching copy must not hide the stale one: the commit check refuses both.
    release.write()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as archive:
        for name, data in windows_members(**{'PatchTrace/dependency-versions.json': versions(OTHER)}).items():
            archive.writestr(name, data)
        with pytest.warns(UserWarning):
            archive.writestr('PatchTrace/dependency-versions.json', versions())
    release.files[WINDOWS_ZIP] = release.files[PORTABLE] = buffer.getvalue()
    release.write()
    code, document, _ = run(release)
    assert code == 3 and failures(document)['archive:windows-zip'] == 'PT-REL-ARCHIVE-CONTENT'
    assert failures(document)['commit:windows-zip'] == 'PT-REL-COMMIT-MISMATCH'


def test_duplicate_json_keys_are_not_last_wins(release):
    text = (f'{{"Python": "3.12.10", "PatchTrace": "{TAG[1:]}", "PatchTrace commit": "{OTHER}", '
            f'"PatchTrace commit": "{SHA}"}}').encode()
    windows_zip(**{'PatchTrace/dependency-versions.json': text})(release)
    code, document, _ = run(release)
    assert code == 3 and failures(document) == {'commit:windows-zip': 'PT-REL-COMMIT-MISMATCH'}


def test_an_oversized_dependency_versions_member_is_refused_unread(release):
    big = versions()[:-1] + b' ' * (vr.MAX_JSON_BYTES + 1) + b'}'
    windows_zip(**{'PatchTrace/dependency-versions.json': big})(release)
    code, document, _ = run(release)
    assert code == 3 and failures(document) == {'archive:windows-zip': 'PT-REL-ARCHIVE-CONTENT',
                                                'commit:windows-zip': 'PT-REL-COMMIT-MISMATCH'}
    assert '1 MiB' in by_id(document)['commit:windows-zip']['detail']


def test_the_member_count_is_capped(release, monkeypatch):
    monkeypatch.setattr(vr, 'MAX_MEMBERS', 2)
    code, document, _ = run(release.write())
    assert code == 3
    assert failures(document)['archive:windows-zip'] == 'PT-REL-ARCHIVE-CONTENT'
    assert failures(document)['archive:linux-tar'] == 'PT-REL-ARCHIVE-CONTENT'
    assert 'more than 2 members' in by_id(document)['archive:windows-zip']['detail']


def test_a_corrupt_zip_fails_its_archive_and_commit_checks(release):
    release.files[WINDOWS_ZIP] = release.files[PORTABLE] = b'PK not a zip'
    code, document, _ = run(release.write())
    assert code == 3 and failures(document) == {'archive:windows-zip': 'PT-REL-ARCHIVE-CONTENT',
                                                'commit:windows-zip': 'PT-REL-COMMIT-MISMATCH'}


def test_a_linux_commit_is_checked_once_the_package_records_one(release):
    members = [LINUX_MEMBERS[0], ('PatchTrace/dependency-versions.json', versions(), 0o644)]
    linux_tar(members)(release)
    code, document, _ = run(release)
    assert code == 0 and by_id(document)['commit:linux-tar']['status'] == 'pass'
    members[1] = ('PatchTrace/dependency-versions.json', versions(commit=OTHER), 0o644)
    linux_tar(members)(release)
    code, document, _ = run(release)
    assert code == 3 and failures(document) == {'commit:linux-tar': 'PT-REL-COMMIT-MISMATCH'}


def test_an_internal_relative_symlink_is_allowed(release):
    linux_tar(LINUX_MEMBERS, (('PatchTrace/_internal/libz.so', 'libz.so.1'),))(release)
    code, document, _ = run(release)
    assert code == 0, failures(document)


# ---------------------------------------------------------------- hostile text stays bounded and on one line

def test_hostile_release_values_are_bounded_and_escaped(release):
    hostile = 'v0.1.0\n\x1b[31mFAKE pass\r' + 'x' * 5000
    meta(tagName=hostile, targetCommitish='main\npass commit:target')(release.write())
    out, err = io.StringIO(), io.StringIO()
    assert vr.main(release.argv(), out=out, err=err) == 3
    for line in out.getvalue().splitlines():
        assert '\x1b' not in line and '\r' not in line and len(line) <= 400
    assert not any(line.startswith('pass') and 'commit:target' in line for line in out.getvalue().splitlines())


# ---------------------------------------------------------------- record, usage and unreadable input

def test_the_record_holds_tag_peeled_sha_sizes_and_hashes(release):
    release.write()
    code, _, _ = run(release, '--record', str(release.record_path))
    record = release.record_path.read_bytes().decode('utf-8')
    assert code == 0 and '\r' not in record
    assert TAG in record and f'`{SHA}`' in record
    for name, data in release.files.items():
        assert re.search(rf'\| `{re.escape(name)}` \| {len(data)} \| `{digest(data)}` \|', record)
        sidecar = release.sidecar(name)
        assert re.search(rf'\| `{re.escape(name)}\.sha256` \| {len(sidecar)} \| `{digest(sidecar)}` \|', record)
    assert 'not-checked: commit:linux-tar' in record and 'exit 0' in record


def test_the_record_names_the_failing_checks(release):
    release.write()
    tampered_byte(release)
    code, _, _ = run(release, '--record', str(release.record_path))
    record = release.record_path.read_text(encoding='utf-8')
    assert code == 3 and f'fail: hash:{SETUP}' in record and 'exit 3' in record


def test_help_prints_the_commands_that_produce_the_inputs():
    out, err = io.StringIO(), io.StringIO()
    assert vr.main(['--help'], out=out, err=err) == 0
    text = out.getvalue()
    assert 'gh release view TAG --json tagName,isPrerelease,isDraft,targetCommitish,assets,body' in text
    assert "git ls-remote --tags origin refs/tags/TAG 'refs/tags/TAG^{}'" in text
    assert 'gh release download TAG --dir DIR' in text


def malformed_json(release: Release) -> None:
    release.json_path.write_text('{"tagName": ', encoding='utf-8', newline='\n')


def json_list(release: Release) -> None:
    release.json_path.write_text('[]', encoding='utf-8', newline='\n')


def json_nan(release: Release) -> None:
    release.json_path.write_text('{"tagName": NaN}', encoding='utf-8', newline='\n')


def json_missing(release: Release) -> None:
    release.json_path.unlink()


def peeled_garbage(release: Release) -> None:
    release.peeled_path.write_text('not a listing\n', encoding='utf-8', newline='\n')


def dir_missing(release: Release) -> None:
    for path in release.dir.iterdir():
        path.unlink()
    release.dir.rmdir()


UNREADABLE = {'bad-json': malformed_json, 'json-list': json_list, 'json-nan': json_nan,
              'no-json': json_missing, 'peeled-junk': peeled_garbage, 'no-dir': dir_missing}


@pytest.mark.parametrize('case', list(UNREADABLE), ids=list(UNREADABLE))
def test_unreadable_input_exits_2(release, case):
    release.write()
    UNREADABLE[case](release)
    code, document, err = run(release)
    assert code == 2 and document == {} and 'verify_release: error' in err


def test_an_oversized_release_json_exits_2(release, monkeypatch):
    monkeypatch.setattr(vr, 'MAX_INPUT_BYTES', 64)
    code, _, err = run(release.write())
    assert code == 2 and 'larger than' in err


BAD_ARGS = {'short-sha': ['--sha', 'abc'], 'upper-sha': ['--sha', 'A' * 40], 'no-v': ['--tag', '0.1.0-beta.1'],
            'unknown': ['--bogus']}


@pytest.mark.parametrize('case', list(BAD_ARGS), ids=list(BAD_ARGS))
def test_usage_errors_exit_2(release, case):
    release.write()
    out, err = io.StringIO(), io.StringIO()
    assert vr.main([*release.argv(), *BAD_ARGS[case]], out=out, err=err) == 2
    assert out.getvalue() == '' and 'verify_release: error' in err.getvalue()


# ---------------------------------------------------------------- source invariants

def test_the_tool_is_offline_stdlib_and_names_no_update_endpoint():
    text = TOOL.read_text(encoding='utf-8')
    assert 'api.github' not in text and 'releases/latest' not in text
    imports = set(re.findall(r'^(?:from|import) ([\w.]+)', text, re.MULTILINE))
    assert not imports & {'subprocess', 'socket', 'urllib', 'urllib.request', 'http', 'http.client', 'requests'}
    assert 'extractall' not in text and '.extract(' not in text
