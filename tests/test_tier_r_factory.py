"""SPEC-32 factory end to end on tiny synthetic C compiled inside the tests: reproducible PE builds, PDB/DWARF
inventories, masked body hashes, the decision table, authored-suite cross-checks, A/A and toolchain-noise pairs.
Needs clang + lld-link + LLVM tools (msvc-free) and optionally mingw-w64; missing tools are recorded as BLOCKED."""
from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from tier_r_helpers import ROOT, require, write_tree

from tools.calibration.tier_r import contracts as C
from tools.calibration.tier_r import factory as F
from tools.calibration.tier_r.labeler import label_diff
from tools.calibration.tier_r.pe import loaded_view, read_pe

SHARED_OLD = '#define SCALE 3\nint ka_clamp(int v, int hi);\n'
SHARED_NEW = '#define SCALE 4\nint ka_clamp(int v, int hi);\n'
A_OLD = '''#include "shared.h"
static __attribute__((noinline)) int helper(int v) { return v + 11; }
int ka_scale(int v) { return helper(v) * SCALE; }
int ka_clamp(int v, int hi)
{
    if (v > hi) {
        return hi;
    }
    return v;
}
int ka_sum(const int *p, int n)
{
    int t = 0; /* running total */
    for (int i = 0; i < n; i++) {
        t += p[i];
    }
    return t;
}
int ka_tail(int v)
{
#if 0
    v += 1;
#endif
    return ka_clamp(v, 100) + 1;
}
'''
A_NEW = '''#include "shared.h"
static __attribute__((noinline)) int helper(int v) { return v + 11; }
int ka_scale(int v) { return helper(v) * SCALE; }
int ka_clamp(int v, int hi)
{
    if (hi < 0) {
        return 0;
    }
    if (v > hi) {
        return hi;
    }
    return v;
}
int ka_sum(const int *p, int n)
{
    int t = 0; /* the running total of all elements */

    for (int i = 0; i < n; i++) {
        t += p[i];
    }
    return t;
}
int ka_tail(int v)
{
#if 0
    v += 2;
#endif
    return ka_clamp(v, 100) + 1;
}
int ka_new(const int *p, int n)
{
    int m = 0;
    for (int i = 0; i < n; i++) {
        if (p[i] > m) {
            m = p[i] * 3 + (m >> 1);
        }
    }
    return m * 5 - 1;
}
'''
B_OLD = '''#include "shared.h"
int kb_old(int v) { return v * 9; }
static __attribute__((noinline)) int helper(int v) { return v ^ 0x5a; }
int kb_mix(int v) { return helper(v) + ka_clamp(v, 9); }
int kb_keep(int v) { return v - 7; }
'''
B_NEW = '''#include "shared.h"
static __attribute__((noinline)) int helper(int v) { return v ^ 0x5a; }
int kb_mix(int v) { return helper(v) + ka_clamp(v, 9); }
int kb_keep(int v) { return v - 7; }
'''


def base(root: Path, files: dict[str, str], tag: str, profile: str = 'msvc-free') -> F.BaseSource:
    write_tree(root, files)
    return F.BaseSource(project='kademo', lineage='L-kademo', family='synthetic',
                        source={'suite': 'tests/kademo', 'version': tag, 'license_spdx': 'MIT'}, root=root,
                        files=tuple(sorted(f for f in files if f.endswith('.c'))), output='kademo.dll',
                        profile=profile, std='c11', tag=tag)


@pytest.fixture(scope='module')
def store(tmp_path_factory):
    return tmp_path_factory.mktemp('calib') / 'known-answer'


@pytest.fixture(scope='module')
def trees(tmp_path_factory):
    root = tmp_path_factory.mktemp('src')
    old = {'shared.h': SHARED_OLD, 'a.c': A_OLD, 'b.c': B_OLD}
    new = {'shared.h': SHARED_NEW, 'a.c': A_NEW, 'b.c': B_NEW}
    return root / 'old', old, root / 'new', new


def pair(session, trees, profile):
    old_root, old_files, new_root, new_files = trees
    ob = base(old_root / profile, old_files, 'old', profile)
    nb = base(new_root / profile, new_files, 'new', profile)
    old = session.side(session.build(ob.spec(variant='old')), ob.root)
    new = session.side(session.build(nb.spec(variant='new')), nb.root)
    return ob, nb, old, new


EXPECTED = {'ka_clamp': ('changed', 'different'), 'ka_sum': ('cosmetic', 'identical'),
            'ka_tail': ('ambiguous', None), 'ka_scale': ('ambiguous', 'different'), 'kb_keep': ('unchanged', None),
            'kb_mix': ('unchanged', 'address-only'), 'ka_new': ('no-counterpart', 'n/a'),
            'kb_old': ('no-counterpart', 'n/a')}


@pytest.mark.parametrize('profile', ['msvc-free', 'mingw-gcc'])
def test_decision_table_on_real_builds(record_live_status, store, trees, profile):
    tools = require(record_live_status, profile)
    session = F.Session(tools, store)
    ob, nb, old, new = pair(session, trees, profile)
    recs = label_diff(old, new, label_source='source-diff',
                      declared_changed={'ka_clamp': 'bounds-check-added', 'kb_keep': 'constant-change'},
                      declared_unchanged=('ka_sum',))
    by = {(r['file'], r['name']): r for r in recs}
    assert {('a.c', 'helper'), ('b.c', 'helper')} <= set(by), 'static name collision resolved by file'
    for (_, name), rec in by.items():
        if name in EXPECTED:
            label, body = EXPECTED[name]
            assert rec['label'] == label, (name, rec)
            if body:
                assert rec['body'] == body, (name, rec)
    assert by[('a.c', 'ka_clamp')]['change_kind'] == 'bounds-check-added' and by[('a.c', 'ka_clamp')]['check'] == 'ok'
    assert by[('b.c', 'kb_keep')]['check'] == 'disagree'           # card claimed a change the evidence refutes
    assert by[('a.c', 'ka_sum')]['check'] == 'ok'
    assert 'inactive' in by[('a.c', 'ka_tail')]['notes'] and 'induced' in by[('a.c', 'ka_scale')]['notes']
    doc = F.finalize(pid=F.pair_id('kademo', profile), stratum='release', method='release-pair', base_old=ob,
                     base_new=nb, old=old, new=new, label_source='source-diff', functions=recs, case={})
    assert C.load_labels(C.dump_json(doc)).summary.disagreements == 1
    assert doc['older']['build']['profile'] == profile


def test_build_is_reproducible_and_engine_image_is_stripped(record_live_status, store, trees, tmp_path):
    tools = require(record_live_status, 'msvc-free')
    old_root, old_files, _, _ = trees
    b = base(tmp_path / 'copy', old_files, 'old')
    first = F.build(b.spec(variant='x'), tools, store)
    second = F.build(b.spec(variant='y'), tools, store)  # another scratch directory and another source copy
    assert (first.sha256, first.debug_sha256, first.pdb_sha256) == (second.sha256, second.debug_sha256,
                                                                   second.pdb_sha256)
    debug, engine = read_pe(first.debug_image), read_pe(first.engine_image)
    assert debug.symbol_count > 0 and engine.symbol_count == 0
    assert loaded_view(debug) == loaded_view(engine) and debug.image_base == engine.image_base == 0x180000000
    assert first.pdb is not None and not (first.engine_image.parent / first.pdb.name).exists()
    record = json.loads((first.debug_image.parent / 'build.json').read_text(encoding='utf-8'))
    assert str(tmp_path) not in json.dumps(record['recipe']), 'recipe digest inputs must not contain scratch paths'


def test_aa_rebuild_layout_and_noise_pairs(record_live_status, store, trees):
    tools = require(record_live_status, 'msvc-free')
    session = F.Session(tools, store)
    old_root, old_files, _, _ = trees
    b = base(old_root / 'aa', old_files, 'old')
    docs = F.run_aa(session, b)
    rebuild = docs[0]
    assert rebuild['method'] == 'aa-rebuild' and rebuild['reproducibility']['byte_identical'] is True
    assert rebuild['older']['sha256'] == rebuild['newer']['sha256']
    assert {f['label'] for f in rebuild['functions']} == {'unchanged'}
    layout = [d for d in docs if d['method'] == 'aa-layout']
    assert layout, 'two objects: reversed link order must shift functions'
    moved = layout[0]
    assert {f['label'] for f in moved['functions']} == {'unchanged'}
    assert any(f['old_rva'] != f['new_rva'] for f in moved['functions'])
    assert {f['body'] for f in moved['functions']} <= {'identical', 'address-only'}
    noise, skipped = F.run_noise(session, b, [('msvc-free', 'O0', 'msvc-free', 'O2')])
    assert noise and not skipped
    assert {f['label'] for f in noise[0]['functions']} <= {'unchanged', 'no-counterpart'}
    assert any(f['body'] == 'different' for f in noise[0]['functions'])
    for doc in docs + noise:
        assert C.load_labels(C.dump_json(doc)).pair_id == doc['pair_id']


def test_authored_suite_labels_and_cross_check(record_live_status, store, tmp_path):
    tools = require(record_live_status, 'msvc-free')
    session = F.Session(tools, store)
    template = ROOT / 'corpus' / 'ours' / '_template' / 'tiny'
    ((doc, problems),) = F.run_suite(session, template)
    assert problems == [] and doc['summary']['disagreements'] == 0 and doc['stratum'] == 'authored'
    labels = {f['name']: (f['label'], f['body']) for f in doc['functions']}
    assert labels == {'tiny_add': ('unchanged', 'identical'), 'tiny_clamp': ('changed', 'different'),
                      'tiny_sum_to': ('cosmetic', 'identical'), 'tiny_old_only': ('no-counterpart', 'n/a'),
                      'tiny_new_only': ('no-counterpart', 'n/a')}
    broken = tmp_path / 'tiny'
    shutil.copytree(template, broken)
    suite = json.loads((broken / 'suite.json').read_text(encoding='utf-8'))
    suite['pairs'][0]['truth'][2] = {'function': 'tiny_sum_to', 'label': 'changed', 'kind': 'other'}  # wrong
    (broken / 'suite.json').write_text(json.dumps(suite), encoding='utf-8')
    ((bad, _),) = F.run_suite(session, broken)
    wrong = next(f for f in bad['functions'] if f['name'] == 'tiny_sum_to')
    assert wrong['check'] == 'disagree' and 'identical' in wrong['notes'] and bad['summary']['disagreements'] == 1


def test_store_refuses_root_inside_worktree(monkeypatch):
    monkeypatch.setenv('PATCHTRACE_CALIB_ROOT', str(ROOT / 'build' / 'calib'))
    with pytest.raises(F.FactoryError, match='inside the work tree'):
        F.store_dir()
