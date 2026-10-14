"""SPEC-32 s10 engine front ends. rz-diff runs through the production registry/scheduler against a FAKE rz-diff script
(a synthetic stand-in, not rizin); BinDiff and Ghidriff read hand-built synthetic files through the production
importer/normaliser. None of this is live engine evidence: absent real tools are asserted as BLOCKED, not skipped."""
from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest
from bindiff_builder import build
from test_tier_r_eval_metrics import FUNCS, make_labels

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import evaluate as E  # noqa: E402

BASE = 0x180000000
LABELS = make_labels(FUNCS, pair_id='syn-eng')


def _store(tmp_path, labels=LABELS, symbols='hidden'):
    for side in (labels.older, labels.newer):
        sha = side.sha256 if symbols == 'hidden' else side.debug_sha256
        folder = tmp_path / 'store' / 'images' / sha
        folder.mkdir(parents=True, exist_ok=True)
        (folder / side.file_name).write_bytes(b'MZ synthetic image placeholder')
    return tmp_path / 'store'


RZ_ENTRIES = [(1.0, 'COMPLETE', 0x1000, 0x1000), (0.9, 'PARTIAL', 0x1020, 0x1020), (1.0, 'COMPLETE', 0x1010, 0x1010),
              (0.0, 'UNLIKE', 0x1060, None)]


def _fake_rz(tmp_path, entries=RZ_ENTRIES, exit_code=0):
    doc = [{'similarity': s, 'type': t, 'original': None if o is None else {'addr': BASE + o, 'name': 'f', 'size': 16},
            'modified': None if n is None else {'addr': BASE + n, 'name': 'f', 'size': 16}} for s, t, o, n in entries]
    script = tmp_path / 'rz-diff'
    script.write_text(f'#!{sys.executable}\nimport sys\n'
                      f'if sys.argv[1:] == ["-v"]:\n    print("rz-diff 0.9.1 (synthetic fake)"); sys.exit(0)\n'
                      f'print({json.dumps(json.dumps(doc))}); sys.exit({exit_code})\n')
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


posix_only = pytest.mark.skipif(os.name == 'nt', reason='fake rz-diff is a shebang script; the Windows leg is CI-only')


@posix_only
def test_rzdiff_through_the_production_adapter(tmp_path):
    provider = E.RzDiffProvider(_store(tmp_path), executable=_fake_rz(tmp_path))
    result = provider(LABELS, 'hidden')
    assert (result.status, result.version) == ('ok', '0.9.1')
    assert sorted((p.old_rva, p.new_rva, p.changed) for p in result.predictions) == [
        (0x1000, 0x1000, False), (0x1010, 0x1010, False), (0x1020, 0x1020, True)]
    assert result.old_only == frozenset({0x1060})
    report = E.evaluate([LABELS], [provider])
    m = report['strata']['authored']['rz-diff']
    assert (m['identity_tp'], m['identity_fp'], m['changed_tp']) == (3, 0, 1)
    assert report['engines'][0]['status'] == 'ok'


@posix_only
def test_rzdiff_failure_is_failed_not_blocked(tmp_path):
    provider = E.RzDiffProvider(_store(tmp_path), executable=_fake_rz(tmp_path, exit_code=3))
    result = provider(LABELS, 'hidden')
    assert result.status == 'failed' and 'rz-diff exited with 3' in result.reason


def test_rzdiff_absent_tool_is_blocked_with_reason(tmp_path):
    provider = E.RzDiffProvider(_store(tmp_path), environ={'PATH': str(tmp_path / 'nothing')})
    result = provider(LABELS, 'hidden')
    assert result.status == 'blocked' and 'rz-diff executable not found' in result.reason


@posix_only
def test_missing_image_is_blocked(tmp_path):
    provider = E.RzDiffProvider(tmp_path / 'empty-store', executable=_fake_rz(tmp_path))
    assert provider(LABELS, 'hidden').status == 'blocked'


@posix_only
def test_visible_symbols_uses_the_debug_images(tmp_path):
    store = _store(tmp_path, symbols='visible')
    provider = E.RzDiffProvider(store, executable=_fake_rz(tmp_path))
    assert provider(LABELS, 'visible').status == 'ok'
    assert provider(LABELS, 'hidden').status == 'blocked'        # stripped images were not stored in this test


def test_bindiff_import_and_orientation(tmp_path):
    imports = tmp_path / 'imports'
    imports.mkdir()
    rows = [(1, BASE + 0x1000, 'a', BASE + 0x1000, 'a', 1.0, 1.0, 0, 7),
            (2, BASE + 0x1020, 'c', BASE + 0x1020, 'c', 0.5, 0.9, 0, 7)]
    target = imports / 'syn-eng.BinDiff'
    build(target, hashes=(LABELS.older.sha256, LABELS.newer.sha256), functions=rows)
    provider = E.BindiffImportProvider(imports)
    result = provider(LABELS, 'hidden')
    assert result.status == 'ok'
    assert [(p.old_rva, p.changed) for p in result.predictions] == [(0x1000, False), (0x1020, True)]
    target.unlink()
    build(target, hashes=(LABELS.newer.sha256, LABELS.older.sha256), functions=rows)
    reversed_ = provider(LABELS, 'hidden')
    assert reversed_.status == 'failed' and 'reversed' in reversed_.reason


@pytest.mark.parametrize('imports', [None, 'empty'], ids=['no-folder', 'empty-folder'])
def test_bindiff_without_import_is_blocked(tmp_path, imports):
    folder = tmp_path if imports else None
    result = E.BindiffImportProvider(folder)(LABELS, 'hidden')
    assert result.status == 'blocked' and 'syn-eng.BinDiff' in result.reason


def _ghidriff(labels=LABELS):
    def fn(name, addr):
        return {'name': name, 'fullname': name, 'address': addr}
    return {'old_meta': {'Executable SHA256': labels.older.sha256}, 'new_meta': {'Executable SHA256': labels.newer.sha256},
            'functions': {'added': [fn('H', f'{BASE + 0x1070:x}')], 'deleted': [fn('G', f'{BASE + 0x1060:x}')],
                          'modified': [{'old': fn('C', f'{BASE + 0x1020:x}'), 'new': fn('C', f'{BASE + 0x1020:x}'),
                                        'ratio': 0.75, 'match_types': ['ExactBytes'], 'diff_type': ['code']}]}}


def test_ghidriff_import_marks_unlisted_as_implicit(tmp_path):
    (tmp_path / 'syn-eng.ghidriff.json').write_text(json.dumps(_ghidriff()))
    provider = E.GhidriffImportProvider(tmp_path)
    result = provider(LABELS, 'hidden')
    assert result.status == 'ok' and result.implicit_unchanged
    assert [(p.old_rva, p.new_rva, p.changed, p.similarity_milli) for p in result.predictions] == [
        (0x1020, 0x1020, True, 750)]
    assert (result.old_only, result.new_only) == (frozenset({0x1060}), frozenset({0x1070}))
    report = E.evaluate([LABELS], [provider])
    assert any('upper bound' in n for n in report['notes'])
    assert report['strata']['authored']['ghidriff']['identity_tp'] == 6


def test_ghidriff_wrong_hash_or_bad_json_is_failed(tmp_path):
    bad = _ghidriff()
    bad['old_meta']['Executable SHA256'] = 'f' * 64
    path = tmp_path / 'syn-eng.ghidriff.json'
    path.write_text(json.dumps(bad))
    result = E.GhidriffImportProvider(tmp_path)(LABELS, 'hidden')
    assert result.status == 'failed' and 'does not match' in result.reason
    path.write_text('{"functions": NaN}')
    assert E.GhidriffImportProvider(tmp_path)(LABELS, 'hidden').status == 'failed'


def test_ghidriff_absent_import_is_blocked(tmp_path):
    result = E.GhidriffImportProvider(tmp_path)(LABELS, 'hidden')
    assert result.status == 'blocked' and 'Ghidra/Java/Ghidriff are not run' in result.reason
