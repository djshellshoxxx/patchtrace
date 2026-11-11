"""`patchtrace profile list|show|validate|save|delete` through the real entry point (`patchtrace.cli.main`), so the
registry adapter is covered too. Every test passes `--profiles-dir` (or redirects the per-user directory into
`tmp_path`), so the real profile folder is never read or written. Hermetic: small JSON files, no network, no process."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace import cli
from patchtrace.cli_commands import discover
from patchtrace.enrichment import profiles
from patchtrace.enrichment.profiles import AnalysisProfile, ProfileStore, profile_digest

SRC = Path(__file__).resolve().parents[1] / 'src'
TRIAGE = AnalysisProfile(name='triage', symbol_policy='local', snapshot_max_age_days=7)


def run(capsys, *argv):
    code = cli.main([str(item) for item in argv])
    out, err = capsys.readouterr()
    return code, out, err


def jrun(capsys, *argv):
    code, out, err = run(capsys, *argv, '--json')
    assert out.endswith('\n') and out.count('\n') == 1, out  # exactly one document
    doc = json.loads(out)
    assert doc['contract'] == 'enrichment-cli/1' and set(doc) >= {'command', 'status', 'result', 'warnings'}
    return code, doc, err


def tree(root: Path) -> dict[str, str]:
    """Every directory and file under `root` with the file's SHA-256: equal trees mean nothing was written."""
    if not root.exists():
        return {'': 'absent'}
    return {path.relative_to(root).as_posix(): 'dir' if path.is_dir() else hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*'))}


def write_profile(path: Path, profile: AnalysisProfile = TRIAGE) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(profiles.dumps(profile), encoding='utf-8', newline='\n')
    return path


@pytest.fixture
def store(tmp_path) -> Path:
    return tmp_path / 'profiles'


@pytest.fixture
def source(tmp_path) -> Path:
    return write_profile(tmp_path / 'in' / 'triage-source.json')


# --- registry ------------------------------------------------------------------------------------------------

def test_the_verb_is_discovered_and_listed_by_help(capsys):
    found, failed = discover()
    assert 'profile' in found and 'profile' not in failed
    code, out, _err = run(capsys, '--help')
    assert code == 0 and 'profile' in out
    code, out, _err = run(capsys, 'profile', '--help')
    assert code == 0 and all(leaf in out for leaf in ('list', 'show', 'validate', 'save', 'delete'))


# --- list ----------------------------------------------------------------------------------------------------

def test_list_of_a_missing_directory_shows_only_the_default_and_creates_nothing(store, capsys):
    code, doc, _err = jrun(capsys, 'profile', 'list', '--profiles-dir', store)
    assert (code, doc['command'], doc['status']) == (0, 'profile list', 'complete')
    result = doc['result']
    assert result['contract'] == 'profile-cli/1' and result['profiles_dir'] == str(store)
    assert result['profiles'] == [{'name': 'default', 'digest': profile_digest(profiles.DEFAULT_PROFILE),
                                   'builtin': True}]
    assert result['invalid'] == [] and result['truncated'] is False and doc['warnings'] == []
    assert not store.exists()


def test_list_puts_the_default_first_then_names_in_case_insensitive_order(store, capsys):
    for name in ('zeta', 'Alpha', 'beta'):
        ProfileStore(store).save(TRIAGE.model_copy(update={'name': name}))
    before = tree(store)
    code, doc, _err = jrun(capsys, 'profile', 'list', '--profiles-dir', store)
    assert code == 0
    assert [row['name'] for row in doc['result']['profiles']] == ['default', 'Alpha', 'beta', 'zeta']
    assert {row['digest'] for row in doc['result']['profiles'][1:]} == {profile_digest(TRIAGE)}
    assert [row['builtin'] for row in doc['result']['profiles']] == [True, False, False, False]
    assert tree(store) == before
    code, out, err = run(capsys, 'profile', 'list', '--profiles-dir', store)
    assert code == 0 and err == ''
    lines = out.splitlines()
    assert lines[0].split() == ['default', profile_digest(profiles.DEFAULT_PROFILE), '(built-in)']
    assert [line.split() for line in lines[1:]] == [[name, profile_digest(TRIAGE)] for name in ('Alpha', 'beta', 'zeta')]


def test_list_reports_an_invalid_file_as_a_warning_and_still_lists_the_valid_ones(store, capsys):
    ProfileStore(store).save(TRIAGE)
    (store / 'broken.json').write_text('{"contract": "profile/1", "name": "broken", "weights": true}',
                                       encoding='utf-8')
    before = tree(store)
    code, doc, _err = jrun(capsys, 'profile', 'list', '--profiles-dir', store)
    assert (code, doc['status']) == (3, 'partial')
    assert [row['name'] for row in doc['result']['profiles']] == ['default', 'triage']
    assert len(doc['result']['invalid']) == 1 and 'weights' in doc['result']['invalid'][0]
    assert doc['warnings'] == [f'invalid profile file: {doc["result"]["invalid"][0]}']
    assert tree(store) == before  # an invalid file is reported, never repaired or removed
    code, out, err = run(capsys, 'profile', 'list', '--profiles-dir', store)
    assert code == 3 and 'triage' in out and err.startswith('warning: invalid profile file: ')


def test_a_stored_file_named_default_never_shadows_the_builtin(store, capsys):
    write_profile(store / 'default.json', profiles.DEFAULT_PROFILE.model_copy(update={'symbol_policy': 'online'}))
    code, doc, _err = jrun(capsys, 'profile', 'list', '--profiles-dir', store)
    assert (code, doc['status']) == (3, 'partial')
    assert doc['result']['profiles'] == [{'name': 'default', 'digest': profile_digest(profiles.DEFAULT_PROFILE),
                                          'builtin': True}]
    assert doc['result']['invalid'] == ['default.json: the name is reserved for the built-in profile; '
                                        'the file is ignored']


def test_list_is_bounded_and_says_when_it_stopped(store, capsys, monkeypatch):
    from patchtrace.enrichment import profile_cli
    for name in ('a1', 'b2', 'c3'):
        ProfileStore(store).save(TRIAGE.model_copy(update={'name': name}))
    monkeypatch.setattr(profile_cli, 'MAX_LISTED', 2)
    code, doc, _err = jrun(capsys, 'profile', 'list', '--profiles-dir', store)
    assert (code, doc['status']) == (3, 'partial')
    assert [row['name'] for row in doc['result']['profiles']] == ['default', 'a1', 'b2']
    assert doc['result']['truncated'] is True and 'first 2 of 3' in doc['warnings'][-1]


def test_the_default_directory_is_the_desktop_profile_directory(tmp_path, capsys, monkeypatch):
    for variable in ('XDG_CONFIG_HOME', 'APPDATA', 'HOME', 'USERPROFILE'):
        monkeypatch.setenv(variable, str(tmp_path / 'user'))
    expected = profiles.default_profiles_dir()
    assert expected.is_relative_to(tmp_path)  # the redirect worked: the real directory is not touched
    ProfileStore(expected).save(TRIAGE)
    code, doc, _err = jrun(capsys, 'profile', 'list')
    assert code == 0 and doc['result']['profiles_dir'] == str(expected)
    assert [row['name'] for row in doc['result']['profiles']] == ['default', 'triage']


def test_a_profiles_dir_that_is_a_file_is_refused(tmp_path, capsys):
    blocker = tmp_path / 'not-a-directory'
    blocker.write_text('x', encoding='utf-8')
    for leaf in (['list'], ['show', 'default'], ['delete', 'triage', '--confirm']):
        code, doc, err = jrun(capsys, 'profile', *leaf, '--profiles-dir', blocker)
        assert (code, doc['status'], doc['result']) == (2, 'failed', None), leaf
        assert 'is not a directory' in doc['error'] and err.startswith('error: ')
    assert blocker.read_text(encoding='utf-8') == 'x'


# --- show ----------------------------------------------------------------------------------------------------

def test_show_the_builtin_default(store, capsys):
    code, doc, _err = jrun(capsys, 'profile', 'show', 'default', '--profiles-dir', store)
    assert (code, doc['command'], doc['status']) == (0, 'profile show', 'complete')
    result = doc['result']
    assert (result['source'], result['name']) == ('built-in', 'default')
    assert result['digest'] == profile_digest(profiles.DEFAULT_PROFILE)
    assert result['profile'] == profiles.DEFAULT_PROFILE.model_dump(mode='json')
    assert not store.exists()


def test_show_a_stored_name_and_a_file_agree_and_write_nothing(store, source, capsys):
    ProfileStore(store).save(TRIAGE)
    before = tree(store.parent)
    code, by_name, _err = jrun(capsys, 'profile', 'show', 'triage', '--profiles-dir', store)
    assert code == 0 and by_name['result']['source'] == 'stored'
    code, by_file, _err = jrun(capsys, 'profile', 'show', source, '--profiles-dir', store)
    assert code == 0 and by_file['result']['source'] == 'file'
    for doc in (by_name, by_file):
        assert doc['result']['profile'] == TRIAGE.model_dump(mode='json')
        assert doc['result']['digest'] == profile_digest(TRIAGE)
    assert tree(store.parent) == before


def test_show_text_is_the_stored_json_and_the_digest(store, capsys):
    ProfileStore(store).save(TRIAGE)
    code, out, err = run(capsys, 'profile', 'show', 'triage', '--profiles-dir', store)
    assert code == 0 and err == ''
    body, _, last = out.rstrip('\n').rpartition('\n')
    assert body + '\n' == profiles.dumps(TRIAGE) == (store / 'triage.json').read_text(encoding='utf-8')
    assert last == f'digest: {profile_digest(TRIAGE)}'


@pytest.mark.parametrize(('argument', 'needle'), [
    ('missing', 'not found'),
    ('bad name!', 'invalid profile name'),
    ('no-such-file.json', 'not an existing regular file'),
], ids=['unknown-name', 'invalid-name', 'missing-file'])
def test_show_refusals_exit_2(store, capsys, argument, needle):
    ProfileStore(store).save(TRIAGE)
    before = tree(store)
    code, doc, err = jrun(capsys, 'profile', 'show', argument, '--profiles-dir', store)
    assert (code, doc['status'], doc['result']) == (2, 'failed', None)
    assert needle in doc['error'] and err.startswith('error: ') and err.count('\n') == 1
    assert tree(store) == before


def test_the_file_or_name_rule_is_the_one_of_the_profile_flag(store, source, tmp_path):
    """`show` decides file or name itself (to refuse a non-regular file first); pin it to `profiles.resolve`."""
    from patchtrace.enrichment import profile_cli
    ProfileStore(store).save(TRIAGE)
    for value, is_file in ((str(source), True), ('triage', False), ('sub/triage', True), ('sub\\triage', True),
                           ('triage.json', True), ('default', False)):
        assert profile_cli.is_file_argument(value) is is_file, value
    assert profiles.resolve('triage', ProfileStore(store)) == profiles.resolve(str(source), ProfileStore(store))


# --- validate ------------------------------------------------------------------------------------------------

def test_validate_accepts_a_good_file_and_stores_nothing(store, source, capsys):
    before = tree(source.parent)
    code, doc, _err = jrun(capsys, 'profile', 'validate', source, '--profiles-dir', store)
    assert (code, doc['command'], doc['status']) == (0, 'profile validate', 'complete')
    assert doc['result'] == {'contract': 'profile-cli/1', 'valid': True, 'name': 'triage',
                             'digest': profile_digest(TRIAGE), 'reserved': False, 'name_taken': False}
    assert doc['warnings'] == [] and not store.exists() and tree(source.parent) == before
    code, out, err = run(capsys, 'profile', 'validate', source, '--profiles-dir', store)
    assert (code, err) == (0, '') and out == f'valid profile triage (digest {profile_digest(TRIAGE)})\n'


def test_validate_warns_about_a_reserved_or_taken_name(store, tmp_path, source, capsys):
    ProfileStore(store).save(TRIAGE.model_copy(update={'name': 'Triage'}))
    code, doc, _err = jrun(capsys, 'profile', 'validate', source, '--profiles-dir', store)
    assert code == 0 and doc['result']['name_taken'] is True and '--force' in doc['warnings'][0]
    reserved = write_profile(tmp_path / 'in' / 'reserved.json', profiles.DEFAULT_PROFILE)
    code, doc, _err = jrun(capsys, 'profile', 'validate', reserved, '--profiles-dir', store)
    assert code == 0 and doc['result']['reserved'] is True and 'built-in' in doc['warnings'][0]


BAD_FILES = {
    'not-json': (b'{not json', 'JSON'),
    'unknown-key': (json.dumps(TRIAGE.model_dump(mode='json') | {'api_key': 'x'}).encode(), 'api_key'),
    'coerced-bool': (json.dumps(TRIAGE.model_dump(mode='json') | {'snapshot_max_age_days': True}).encode(),
                     'snapshot_max_age_days'),
    'unknown-detector': (json.dumps(TRIAGE.model_dump(mode='json') | {'enabled': ['no-such-detector']}).encode(),
                         'enabled'),
    'wrong-contract': (json.dumps(TRIAGE.model_dump(mode='json') | {'contract': 'profile/2'}).encode(), 'contract'),
    'too-large': (b' ' * (profiles.MAX_FILE_BYTES + 1), 'exceeds'),
    'empty': (b'', 'JSON'),
}


@pytest.mark.parametrize('case', list(BAD_FILES), ids=list(BAD_FILES))
def test_validate_refuses_a_bad_file_with_exit_2_and_one_line(store, tmp_path, capsys, case):
    body, needle = BAD_FILES[case]
    bad = tmp_path / 'bad.json'
    bad.write_bytes(body)
    code, doc, err = jrun(capsys, 'profile', 'validate', bad, '--profiles-dir', store)
    assert (code, doc['status'], doc['result']) == (2, 'failed', None)
    assert needle in doc['error'] and err.startswith('error: ') and err.count('\n') == 1
    assert not store.exists()


def test_validate_refuses_a_missing_file_and_a_directory(store, tmp_path, capsys):
    for target in (tmp_path / 'absent.json', tmp_path):
        code, doc, _err = jrun(capsys, 'profile', 'validate', target, '--profiles-dir', store)
        assert (code, doc['result']) == (2, None) and 'not an existing regular file' in doc['error']


def test_a_hostile_field_name_is_bounded_and_escaped_in_the_refusal(store, tmp_path, capsys):
    hostile = '\x1b[31m' + 'A' * 20_000
    bad = tmp_path / 'hostile.json'
    bad.write_text(json.dumps(TRIAGE.model_dump(mode='json') | {hostile: 1}), encoding='utf-8')
    code, doc, err = jrun(capsys, 'profile', 'validate', bad, '--profiles-dir', store)
    assert code == 2 and len(doc['error']) <= 500
    assert '\x1b' not in err and '\\u001b[31m' in err  # the escape sequence is spelled, never sent
    code, _out, err = run(capsys, 'profile', 'save', bad, '--profiles-dir', store)
    assert code == 2 and '\x1b' not in err and len(err) <= 600 and not store.exists()


# --- save ----------------------------------------------------------------------------------------------------

def test_save_stores_the_profile_where_the_desktop_reads_it(store, source, capsys):
    code, doc, _err = jrun(capsys, 'profile', 'save', source, '--profiles-dir', store)
    assert (code, doc['command'], doc['status']) == (0, 'profile save', 'complete')
    assert doc['result'] == {'contract': 'profile-cli/1', 'name': 'triage', 'digest': profile_digest(TRIAGE),
                             'path': str(store / 'triage.json'), 'replaced': False}
    assert tree(store) == {'triage.json': hashlib.sha256(profiles.dumps(TRIAGE).encode()).hexdigest()}
    assert ProfileStore(store).get('triage') == TRIAGE
    code, shown, _err = jrun(capsys, 'profile', 'show', 'triage', '--profiles-dir', store)
    assert code == 0 and shown['result']['digest'] == doc['result']['digest']


def test_save_refuses_a_taken_name_unless_forced(store, source, tmp_path, capsys):
    ProfileStore(store).save(TRIAGE)
    changed = write_profile(tmp_path / 'in' / 'changed.json', TRIAGE.model_copy(update={'symbol_policy': 'disabled'}))
    before = tree(store)
    code, doc, _err = jrun(capsys, 'profile', 'save', changed, '--profiles-dir', store)
    assert (code, doc['result']) == (2, None) and 'already exists' in doc['error'] and '--force' in doc['error']
    assert tree(store) == before
    code, doc, _err = jrun(capsys, 'profile', 'save', changed, '--profiles-dir', store, '--force')
    assert code == 0 and doc['result']['replaced'] is True
    assert ProfileStore(store).get('triage').symbol_policy == 'disabled'
    assert sorted(tree(store)) == ['triage.json']  # no temporary file is left next to it


def test_force_replaces_a_stored_name_that_differs_only_in_case(store, source, capsys):
    ProfileStore(store).save(TRIAGE.model_copy(update={'name': 'Triage'}))
    code, doc, _err = jrun(capsys, 'profile', 'save', source, '--profiles-dir', store)
    assert code == 2 and 'already exists' in doc['error']
    code, doc, _err = jrun(capsys, 'profile', 'save', source, '--profiles-dir', store, '--force')
    assert code == 0 and doc['result']['replaced'] is True
    assert ProfileStore(store).names() == ['triage']  # one profile, not two names that collide on Windows


def test_save_under_another_name(store, source, capsys):
    code, doc, _err = jrun(capsys, 'profile', 'save', source, '--profiles-dir', store, '--name', 'Field Lab 2')
    assert code == 0 and doc['result']['name'] == 'Field Lab 2'
    stored = ProfileStore(store).get('Field Lab 2')
    assert stored == TRIAGE.model_copy(update={'name': 'Field Lab 2'}) and profile_digest(stored) == profile_digest(TRIAGE)
    code, out, _err = run(capsys, 'profile', 'save', source, '--profiles-dir', store, '--name', 'second')
    assert code == 0 and out == f'saved profile second to {store / "second.json"}\n'


@pytest.mark.parametrize(('name', 'needle'), [
    ('default', 'read-only'), ('Default', 'read-only'), ('../escape', 'name: '), ('con', 'reserved on Windows'),
    ('trailing.', 'name: '), ('', 'name: ')],
    ids=['reserved', 'reserved-case', 'traversal', 'windows-device', 'trailing-dot', 'empty'])
def test_save_refuses_a_bad_or_reserved_name(store, source, tmp_path, capsys, name, needle):
    before = tree(tmp_path)
    code, doc, _err = jrun(capsys, 'profile', 'save', source, '--profiles-dir', store, '--name', name)
    assert (code, doc['command'], doc['status'], doc['result']) == (2, 'profile save', 'failed', None)
    assert needle in doc['error']
    assert tree(tmp_path) == before  # nothing stored, nothing written outside the directory


def test_save_of_a_file_named_default_is_refused(store, tmp_path, capsys):
    reserved = write_profile(tmp_path / 'in' / 'reserved.json', profiles.DEFAULT_PROFILE)
    code, doc, _err = jrun(capsys, 'profile', 'save', reserved, '--profiles-dir', store, '--force')
    assert code == 2 and 'read-only' in doc['error'] and not store.exists()


def test_a_directory_that_cannot_be_written_is_a_storage_failure(tmp_path, source, capsys):
    blocker = tmp_path / 'blocker'
    blocker.write_text('x', encoding='utf-8')
    code, doc, _err = jrun(capsys, 'profile', 'save', source, '--profiles-dir', blocker / 'profiles')
    assert (code, doc['status'], doc['result']) == (3, 'failed', None)
    assert doc['error'].startswith('cannot write the profile')
    assert blocker.read_text(encoding='utf-8') == 'x'


# --- delete --------------------------------------------------------------------------------------------------

def test_delete_needs_confirm_and_changes_nothing_without_it(store, capsys):
    ProfileStore(store).save(TRIAGE)
    before = tree(store)
    code, doc, _err = jrun(capsys, 'profile', 'delete', 'triage', '--profiles-dir', store)
    assert (code, doc['result']) == (2, None) and '--confirm' in doc['error'] and 'triage' in doc['error']
    assert tree(store) == before


def test_delete_removes_exactly_the_named_profile(store, capsys):
    for name in ('triage', 'keep'):
        ProfileStore(store).save(TRIAGE.model_copy(update={'name': name}))
    code, doc, _err = jrun(capsys, 'profile', 'delete', 'triage', '--confirm', '--profiles-dir', store)
    assert (code, doc['command'], doc['status']) == (0, 'profile delete', 'complete')
    assert doc['result'] == {'contract': 'profile-cli/1', 'name': 'triage', 'deleted': True}
    assert sorted(tree(store)) == ['keep.json']
    code, out, _err = run(capsys, 'profile', 'delete', 'keep', '--confirm', '--profiles-dir', store)
    assert code == 0 and out == 'deleted profile keep\n' and tree(store) == {}


def test_delete_of_a_name_that_is_not_stored_exits_4(store, capsys):
    ProfileStore(store).save(TRIAGE.model_copy(update={'name': 'Triage'}))
    before = tree(store)
    code, doc, _err = jrun(capsys, 'profile', 'delete', 'absent', '--confirm', '--profiles-dir', store)
    assert (code, doc['status']) == (4, 'no-results')
    assert doc['result'] == {'contract': 'profile-cli/1', 'name': 'absent', 'deleted': False}
    assert tree(store) == before
    code, out, err = run(capsys, 'profile', 'delete', 'triage', '--confirm', '--profiles-dir', store)
    assert code == 4 and out == "no stored profile is named 'triage'\n"
    assert "'Triage'" in err and tree(store) == before  # names are matched exactly; the near miss is named


@pytest.mark.parametrize(('name', 'needle'), [('default', 'cannot be deleted'), ('../triage', 'invalid profile name'),
                                               ('a/b', 'invalid profile name')],
                         ids=['builtin', 'traversal', 'separator'])
def test_delete_refuses_the_default_and_an_invalid_name(store, tmp_path, capsys, name, needle):
    ProfileStore(store).save(TRIAGE)
    write_profile(tmp_path / 'triage.json')  # what a traversal would hit
    before = tree(tmp_path)
    code, doc, _err = jrun(capsys, 'profile', 'delete', name, '--confirm', '--profiles-dir', store)
    assert (code, doc['result']) == (2, None) and needle in doc['error']
    assert tree(tmp_path) == before


# --- usage and import cleanliness ----------------------------------------------------------------------------

def test_usage_errors_exit_2(store, capsys):
    for argv in (['profile'], ['profile', 'rename'], ['profile', 'show'], ['profile', 'save']):
        code, _out, err = run(capsys, *argv)
        assert code == 2 and err.startswith('error: patchtrace profile'), (argv, err)


def test_no_leaf_imports_qt(tmp_path, source):
    store = tmp_path / 'profiles'
    code = ('import sys\nfrom patchtrace import cli\n'
            f'store, source = {str(store)!r}, {str(source)!r}\n'
            'codes = [cli.main(argv + ["--profiles-dir", store, "--json"]) for argv in (\n'
            '    ["profile", "validate", source], ["profile", "save", source], ["profile", "list"],\n'
            '    ["profile", "show", "triage"], ["profile", "delete", "triage", "--confirm"])]\n'
            'import patchtrace.enrichment.profile_cli\n'
            'print(codes, sorted(m for m in sys.modules if m.startswith(("PySide6", "patchtrace.ui"))),'
            ' file=sys.stderr)')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, PYTHONPATH=str(SRC)))
    assert result.returncode == 0, result.stderr
    assert result.stderr.strip().splitlines()[-1] == '[0, 0, 0, 0, 0] []'
    assert len(result.stdout.splitlines()) == 5  # one JSON document per call
