"""Properties, determinism and architecture guards of the L1 ladder (SPEC-31 04 s9, 01 s3, 09 s3). SYNTHETIC IR only.

The hypothesis tests are derandomised (docs/qa.md T-29): same inputs, same verdict, on every OS.
"""
from __future__ import annotations

import ast
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path.insert(0, str(TESTS))
from unified_ir_builder import SyntheticIr, assert_partition, random_world  # noqa: E402

from patchtrace.unified.ladder.engine import run_ladder  # noqa: E402
from patchtrace.unified.limits import Budget  # noqa: E402

LADDER = ROOT / 'src' / 'patchtrace' / 'unified' / 'ladder'
FAST = settings(max_examples=60, deadline=None, derandomize=True, database=None,
                suppress_health_check=[HealthCheck.too_slow, HealthCheck.data_too_large])


def rva_pairs(corr, tiers=None):
    return {(corr.older_rva[p.older_fid], corr.newer_rva[p.newer_fid]): p for p in corr.pairs
            if tiers is None or p.tier in tiers}


class Countdown:
    """A cancel event that fires after `limit` polls (the ladder polls it once per budget check)."""

    def __init__(self, limit: int):
        self.limit = limit
        self.polls = 0

    def is_set(self) -> bool:
        self.polls += 1
        return self.polls > self.limit


# ---- invariants on random worlds -----------------------------------------------------------------------------------------------

def spec_of(ir, fid):
    return ir.layout()[1][fid]


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 45))
def test_every_function_has_exactly_one_place_and_pairs_are_one_to_one(seed, n):
    older, newer = random_world(seed, n)
    corr = run_ladder(older, newer)
    assert_partition(corr, len(older.specs), len(newer.specs))
    assert len({p.older_fid for p in corr.pairs}) == len(corr.pairs) == len({p.newer_fid for p in corr.pairs})
    assert [(p.older_fid, p.newer_fid) for p in corr.pairs] == sorted((p.older_fid, p.newer_fid) for p in corr.pairs)
    assert all(p.tier in 'MABC' for p in corr.pairs)
    for p in corr.pairs:                     # I6: no content key ever pairs a thunk, an import or a tiny function
        if p.pass_id in {'P04', 'P05', 'P06', 'P07', 'P08', 'P09', 'P10', 'P11', 'P12', 'P13', 'P14', 'P15'}:
            for ir, fid in ((older, p.older_fid), (newer, p.newer_fid)):
                spec = spec_of(ir, fid)
                assert spec.kind == 'normal' and len(spec.resolved_body()) > 5


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 45), order_old=st.integers(0, 50), order_new=st.integers(0, 50))
def test_permutation_of_input_order_is_invisible(seed, n, order_old, order_new):
    base = run_ladder(*random_world(seed, n))
    shuffled = run_ladder(*random_world(seed, n, row_order_old=order_old, row_order_new=order_new))
    assert base.digest() == shuffled.digest()


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 45))
def test_swapping_sides_mirrors_the_correspondence(seed, n):
    older, newer = random_world(seed, n)
    forward = run_ladder(older, newer)
    backward = run_ladder(newer, older)

    def key(p):
        return (p.older_fid, p.newer_fid, p.pass_id, p.tier, p.family, p.cls, p.round, p.votes, p.chain, p.hints)

    assert sorted(key(p) for p in forward.pairs) == sorted(
        (p.newer_fid, p.older_fid, *key(p)[2:]) for p in backward.pairs)
    mirror_kind = {'duplicate': 'duplicate', 'icf': 'icf', 'inlined-into': 'outlined-from',
                   'outlined-from': 'inlined-into'}
    assert sorted((g.kind, g.older_fids, g.newer_fids) for g in forward.groups) == sorted(
        (mirror_kind[g.kind], g.newer_fids, g.older_fids) for g in backward.groups)
    assert [(i.fid, i.reason, i.hints) for i in forward.older_only] == [
        (i.fid, i.reason, i.hints) for i in backward.newer_only]
    assert forward.older_hubs == backward.newer_hubs and forward.newer_hubs == backward.older_hubs


def tags_of(corr, older, newer, tiers):
    return {(spec_of(older, p.older_fid).tag, spec_of(newer, p.newer_fid).tag) for p in corr.pairs
            if p.tier in tiers}


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 40), extra=st.integers(1, 3))
def test_adding_an_unrelated_function_never_changes_existing_tier_a_pairs(seed, n, extra):
    older, newer = random_world(seed, n)
    before = tags_of(run_ladder(older, newer), older, newer, 'AM')
    for i in range(extra):          # unique in every key, no calls/names/strings: it cannot disturb any bucket
        newer.add(f'unrelated{i}', seed=777_000 + i, n_insn=15, keys={'md_td': 10**15 + i, 'md_bu': 10**16 + i,
                                                                     'n_bb': 99, 'n_edge': 99})
    after = tags_of(run_ladder(older, newer), older, newer, 'AM')
    assert before <= after


@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 45), limit=st.integers(0, 3000))
def test_budget_expiry_yields_a_prefix_of_the_full_run(seed, n, limit):
    older, newer = random_world(seed, n)
    full = run_ladder(older, newer)
    cut = run_ladder(older, newer, budget=Budget(cancel=Countdown(limit), check_every=1))
    if cut.status == 'complete':
        assert cut.digest() == full.digest()
        return
    assert cut.status == 'partial' and cut.stop_reason == 'cancelled' and not cut.groups
    order = [(p.older_fid, p.newer_fid, p.pass_id, p.tier, p.round, p.seq) for p in sorted(full.pairs, key=lambda p: p.seq)]
    got = [(p.older_fid, p.newer_fid, p.pass_id, p.tier, p.round, p.seq) for p in sorted(cut.pairs, key=lambda p: p.seq)]
    assert got == order[:len(got)]
    assert {i.reason for i in cut.older_only + cut.newer_only} <= {'unfinished'}
    assert set(cut.passes_completed) <= set(full.passes_completed)


def test_deadline_exhaustion_is_partial_too():
    older, newer = random_world(1, 30)
    cut = run_ladder(older, newer, budget=Budget(deadline=0.0, check_every=1, clock=lambda: 1.0))
    assert cut.status == 'partial' and cut.stop_reason == 'deadline'
    assert cut.pairs == ()


def test_passes_are_applied_completely_or_not_at_all():
    older, newer = SyntheticIr(), SyntheticIr()
    for i in range(40):
        older.add(f'a{i}', seed=i)
        newer.add(f'a{i}', seed=i)
    full = run_ladder(older, newer)
    for limit in range(0, 60, 3):
        cut = run_ladder(older, newer, budget=Budget(cancel=Countdown(limit), check_every=1))
        if cut.status == 'partial':
            # a pass either contributed all of its pairs or none: the count is 0 or the full P04 yield
            assert len(cut.pairs) in (0, len(full.pairs))


# ---- determinism across processes ---------------------------------------------------------------------------------------------

def test_result_digest_is_stable_across_hash_seeds_and_processes():
    script = textwrap.dedent('''
        import sys
        sys.path[:0] = [sys.argv[1], sys.argv[2]]
        from unified_ir_builder import random_world
        from patchtrace.unified.ladder.engine import run_ladder
        print(run_ladder(*random_world(11, 60)).digest())
    ''')
    digests = set()
    for hash_seed in ('0', '1', '4242'):
        env = {**os.environ, 'PYTHONHASHSEED': hash_seed, 'PYTHONDONTWRITEBYTECODE': '1'}
        out = subprocess.run([sys.executable, '-c', script, str(ROOT / 'src'), str(TESTS)], capture_output=True,
                             text=True, timeout=120, env=env, cwd=str(ROOT), check=True)
        digests.add(out.stdout.strip())
    assert len(digests) == 1 and re.fullmatch(r'[0-9a-f]{64}', digests.pop())


def test_digest_covers_provenance_and_status():
    import dataclasses
    older, newer = random_world(5, 30)
    corr = run_ladder(older, newer)
    assert corr.pairs
    tweaked_pair = dataclasses.replace(corr.pairs[0], tier='C' if corr.pairs[0].tier != 'C' else 'B')
    assert dataclasses.replace(corr, pairs=(tweaked_pair, *corr.pairs[1:])).digest() != corr.digest()
    assert dataclasses.replace(corr, status='partial').digest() != corr.digest()
    seq_changed = dataclasses.replace(corr.pairs[0], seq=999)
    assert dataclasses.replace(corr, pairs=(seq_changed, *corr.pairs[1:])).digest() == corr.digest()   # seq is not content


# ---- atoms -------------------------------------------------------------------------------------------------------------------------

@FAST
@given(seed=st.integers(0, 10**6), n=st.integers(3, 45))
def test_atoms_are_one_per_pair_valid_and_sorted(seed, n):
    older, newer = random_world(seed, n)
    corr = run_ladder(older, newer)
    atoms = corr.atoms()
    assert len(atoms) == len(corr.pairs)
    assert [(a.older_rva, a.newer_rva) for a in atoms] == sorted((a.older_rva, a.newer_rva) for a in atoms)
    for atom, pair in zip(sorted(atoms, key=lambda a: (a.older_rva, a.newer_rva)),
                          sorted(corr.pairs, key=lambda p: (corr.older_rva[p.older_fid], corr.newer_rva[p.newer_fid])),
                          strict=True):
        assert atom.tier == pair.tier and atom.step == pair.step and atom.cls == pair.cls
        assert atom.source == ('pt-bytes' if pair.family == 'F-PT-BYTES' else 'pt-ladder')
        assert atom.cardinality == '1:1'


# ---- architecture guards (01 s3, 09 s3) -----------------------------------------------------------------------------------------

BANNED = ('PySide6', 'urllib', 'http', 'socket', 'ssl', 'subprocess', 'ctypes', 'ghidriff', 'pyghidra', 'jpype', 'os',
          'shutil', 'tempfile', 'threading', 'sqlite3')
ALLOWED_PATCHTRACE = {'patchtrace.unified.limits', 'patchtrace.unified.contracts', 'patchtrace.enrichment.identity'}


def _imports(path: Path):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name, 0
        elif isinstance(node, ast.ImportFrom):
            yield node.module or '', node.level


def test_ladder_imports_only_pure_modules():
    modules = sorted(LADDER.glob('*.py'))
    assert {m.name for m in modules} >= {'engine.py', 'passes.py', 'propagate.py', 'groups.py', 'ports.py', 'side.py',
                                         'state.py', 'types.py', '__init__.py'}
    for path in modules:
        for module, level in _imports(path):
            top = module.split('.')[0]
            assert top not in BANNED, f'{path.name} imports {module}'
            if level == 0 and top == 'patchtrace':
                assert module in ALLOWED_PATCHTRACE, f'{path.name} imports {module}'
            if level >= 2:                                    # relative imports leaving the ladder package
                target = ('.' * level + module)
                assert target in {'..limits', '..contracts', '...enrichment.identity'}, f'{path.name}: {target}'
            assert not module.startswith(('fusion', 'facts')), f'{path.name} imports {module}'


def test_ladder_has_no_qt_in_a_clean_interpreter():
    code = ('import sys\nsys.modules["PySide6"] = None\nsys.path[:0] = [sys.argv[1]]\n'
            'import patchtrace.unified.ladder.engine\nprint("ok")')
    out = subprocess.run([sys.executable, '-c', code, str(ROOT / 'src')], capture_output=True, text=True, timeout=60,
                         check=True, cwd=str(ROOT))
    assert out.stdout.strip() == 'ok'


HEADER = re.compile(r'Portions derived from google/bindiff v8 \(Apache-2\.0\), Copyright 2011-\d{4} Google LLC')


@pytest.mark.parametrize('name', ['passes.py', 'engine.py', 'propagate.py'])
def test_ported_modules_carry_attribution_header(name):
    text = (LADDER / name).read_text(encoding='utf-8')
    head = text[:1500]
    assert HEADER.search(' '.join(head.split())), f'{name} lacks the Apache-2.0 attribution header'
    assert 'modified for PatchTrace' in ' '.join(head.split())
    assert 'third_party/notices/bindiff-v8' in ' '.join(head.split())


def test_no_gpl_origin_is_named_in_ladder_headers_as_a_source():
    for path in LADDER.glob('*.py'):
        head = path.read_text(encoding='utf-8')[:1500].lower()
        for banned in ('derived from ghidriff', 'derived from diaphora', 'derived from patchdiff', 'derived from turbodiff'):
            assert banned not in head, f'{path.name}: {banned}'
