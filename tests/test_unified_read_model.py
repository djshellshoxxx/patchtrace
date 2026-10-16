"""SPEC-31 S4a read model (07 s4, s7, s11): states and precedence, default filter and order, per-source cells, lazy
detail text, hostile text, scale. Pure tests (no Qt); every row is made up in code, so none of it is live evidence."""
from __future__ import annotations

import gzip
import os
import re
import subprocess
import sys
import time
import tracemalloc
from dataclasses import fields
from pathlib import Path
from typing import get_args

import pytest
from unified_read_support import (
    HOSTILE,
    HOSTILE_IDS,
    atom,
    contested_row,
    delta,
    make_facts,
    make_row,
    material,
    publish,
    request,
    source_ref,
)
from unified_s0_fixtures import make_project

import patchtrace
from patchtrace.sample import synthetic_pe
from patchtrace.secondary.evidence_view import BANNED
from patchtrace.service import ProjectService
from patchtrace.unified import pipeline, store
from patchtrace.unified import read_model as rm
from patchtrace.unified import read_text as rt
from patchtrace.unified.contracts import (
    DECISIONS,
    MATERIALITIES,
    ChangeClass,
    Contest,
    ResultKeyInputs,
    SideRef,
    Support,
)
from patchtrace.unified.limits import UnifiedError
from patchtrace.unified.pipeline import UnifiedOptions
from patchtrace.unified.registry import REGISTRY

FORBIDDEN_CHARS = set('\x00\x1b\r\u202e\u2066\u200f\u2028')   # never in any text; "\n" and "\t" only in verbose text


def pair(name, rva, **kw):
    return make_row([(rva, name)], [(rva + 0x80, name)], **kw)


def load(loaded, **kw):
    return rm.load_unified(request(loaded, **kw))


def labels(vm):
    return [r.function_label for r in vm.rows]


def assert_no_banned(text: str) -> None:
    lowered = text.lower()
    for word in BANNED:  # stems match as prefixes, the rest as whole words ('provenance' is fine)
        tail = '' if word in ('probab', 'vulnerab', 'exploit', 'likelihood') else r'\b'
        assert not re.search(r'\b' + re.escape(word) + tail, lowered), (word, text[:400])
    assert '%' not in text, text[:400]


def review_pair(name, rva, cls='constant', old='1', new='2', **kw):
    """A review row and its facts (one delta of class `cls`)."""
    row = pair(name, rva, materiality='review', classes=[cls], **kw)
    return row, make_facts(row, 'review', deltas=[delta(cls, old=old, new=new, channel='C5')])


def base(group: int) -> int:
    return 0x8000 - 0x400 * group      # the rva order runs against the expected order on purpose


def group_fixture(tmp_path):
    """One row for each of the nine order groups (07 s7)."""
    rows, facts = [], []

    def add(row, fact=None):
        rows.append(row)
        facts.extend([] if fact is None else [fact])
    unchanged_contest = contested_row(base(0) + 0x100, base(0) + 0x180, 'contested-unchanged', materiality='unchanged')
    add(unchanged_contest, make_facts(unchanged_contest, 'unchanged', proof='UNCH/1'))
    add(contested_row(base(0), base(0) + 0x80, 'contested'))
    add(*material({'older': [(base(1), 'material')], 'newer': [(base(1) + 0x80, 'material')]}))
    add(*review_pair('review', base(2)))
    pseudo = pair('pseudo', base(3), materiality='cosmetic', classes=['name-only'])
    add(pseudo, make_facts(pseudo, 'cosmetic', proof='COS-PSEUDO/1'))
    add(pair('tentative', base(4), decision='tentative', atoms=[
        atom(tier='B', step='StringsRefsHasher', cls='E-DATA', older=base(4), newer=base(4) + 0x80)]))
    add(pair('candidate', base(4) + 0x10, decision='candidate', support=[], atoms=[
        atom(tier='C', step='SigCallingCalledHasher', cls='E-CALL', older=base(4) + 0x10, newer=base(4) + 0x90)]))
    add(pair('ambiguous', base(4) + 0x20, decision='ambiguous', materiality='not-applicable', support=[], atoms=[
        atom(older=base(4) + 0x20, newer=base(4) + 0xA0, cardinality='1:N')]))
    add(make_row([(base(5), 'older-only')], decision='older-only', materiality='not-applicable', support=[],
                 atoms=[atom(step='deleted', tier='W', older=base(5), newer=None)]))
    add(make_row(newer=[(base(5) + 0x40, 'newer-only')], decision='newer-only', materiality='not-applicable',
                 support=[], atoms=[atom(step='added', tier='W', older=None, newer=base(5) + 0x40)]))
    add(pair('matched-unknown', base(6)))
    addr = pair('cosmetic-addr', base(7), materiality='cosmetic', classes=['address-only'])
    add(addr, make_facts(addr, 'cosmetic', proof='COS-ADDR/1', deltas=[delta('address-only', new=None)]))
    unchanged = pair('unchanged', base(8), materiality='unchanged')
    add(unchanged, make_facts(unchanged, 'unchanged', proof='UNCH/1'))
    return publish(tmp_path / 'groups', rows, facts)


EXPECTED_GROUP_ORDER = ['contested', 'contested-unchanged', 'material', 'review', 'pseudo', 'tentative', 'candidate',
                        'ambiguous', 'older-only', 'newer-only', 'matched-unknown', 'cosmetic-addr', 'unchanged']


# --- boundaries -------------------------------------------------------------------------------------------------------


def test_read_model_has_no_qt():
    code = ('import sys\nsys.modules["PySide6"] = None\n'
            'import patchtrace.unified.read_model, patchtrace.unified.read_text\n'
            'bad = sorted(m for m in sys.modules if m.startswith(("PySide6", "shiboken6", "patchtrace.ui", '
            '"patchtrace.jobs", "patchtrace.unified.pipeline")) and sys.modules[m] is not None)\n'
            'print("BAD", bad)\nraise SystemExit(90 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(Path(patchtrace.__file__).resolve().parents[1]), PYTHONUTF8='1')
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env, timeout=120)
    assert result.returncode == 0 and 'BAD []' in result.stdout, (result.stdout, result.stderr)


def test_vocabulary_is_ascii_and_complete():
    constants = [*rm.STATE_TEXT.values(), *rt.DECISION_LABELS.values(), *rt.DECISION_GLYPHS.values(),
                 *rt.MATERIALITY_LABELS.values(), *rt.TIER_NAMES.values(), *rt.CLASS_NAMES.values(),
                 *rt.DECISION_MEANING.values(), rt.FOOTER, rt.PROVENANCE_HEADER, rt.PROVENANCE_FOOTER,
                 *rm.BADGES.values(), *rm.STALE_REASONS.values(), rm.STALE_FALLBACK, *rm.GROUP_NAMES]
    assert all(text.isascii() for text in constants)
    assert set(rt.DECISION_LABELS) == set(rt.DECISION_GLYPHS) == set(DECISIONS) == set(rm.DECISION_CHIPS)
    assert set(rt.MATERIALITY_LABELS) == set(MATERIALITIES) == set(rm.MATERIALITY_CHIPS)
    assert set(rm.SEVERITY) - {'constant@test'} == set(get_args(ChangeClass))
    assert set(rm.STALE_REASONS) == set(ResultKeyInputs.model_fields)       # a new key input needs its words
    assert [rm.DECISION_CHIPS[d].glyph for d in DECISIONS] == list('=~?!#-+.')
    for table in (rm.DECISION_CHIPS, rm.MATERIALITY_CHIPS, rm.TIER_CHIPS):  # a glyph is unique inside its table
        assert len({c.glyph for c in table.values()}) == len(table)
        assert all(c.glyph.isascii() and c.tone in {'ok', 'caution', 'info', 'muted', 'alt', 'plain'}
                   for c in table.values())
    assert rm.DECISION_CHIPS['contested'].tone == 'caution'                  # a conflict is never an error colour
    assert set(rm.TIER_CHIPS) == set('MABCW') == set(rt.TIER_NAMES)
    assert rm.BADGES['contested'] == '[!] Contested' and rm.BADGES['older-only'] == '[-] Older only'


def test_tooltip_ids_are_data_and_match_the_spec_list():
    spec = ['view_switch', 'run', 'cancel', 'filter_decision', 'filter_change', 'filter_class', 'filter_source',
            'search', 'show_hidden', 'table', 'tab', 'detail', 'goto', 'correct', 'copy', 'explain', 'retry',
            'copy_error', 'stale_banner']
    assert {f'unified.{name}' for name in spec} <= set(rm.TOOLTIP_IDS)
    assert set(rm.TOOLTIP_TEMPLATE_IDS) == {'unified.row', 'unified.cell', 'unified.badge', 'unified.delta'}
    assert rm.source_tooltip_ids() == tuple(f'unified.source.{s.id}' for s in REGISTRY.sources)
    assert len(set(rm.TOOLTIP_IDS)) == len(rm.TOOLTIP_IDS)
    assert all(t.isascii() and '<' not in t and '>' not in t for t in rm.TOOLTIP_IDS)
    assert {c.tip_id for c in rm.FIXED_COLUMNS} <= set(rm.TOOLTIP_IDS)


# --- states (07 s5) -------------------------------------------------------------------------------------------------------


def test_read_model_states_and_precedence(tmp_path):
    ok = publish(tmp_path / 'ok', [pair('f', 0x1000)])
    partial = publish(tmp_path / 'partial', [pair('f', 0x1000)], status='partial',
                      limitations=('raw-missing', 'ir-not-extracted'))
    stale = store.LoadedResult('stale', 'guard-moved', None, None, ok.manifest, ok.directory)
    stale_partial = store.LoadedResult('stale', 'guard-moved', None, None, partial.manifest, partial.directory)

    none = rm.load_unified(rm.UnifiedLoadRequest(None))
    assert (none.state, none.state_text) == ('U0', 'Open a project to see the unified comparison.')
    for loaded in (None, store.LoadedResult('none', 'no-result')):
        vm = load(loaded)
        assert (vm.state, vm.rows) == ('U1', ())
        assert vm.state_text.startswith('No unified result yet. The primary Ghidriff view is unchanged.')
    assert load(ok, extraction_configured=True).state == 'U3'
    vm = load(partial, extraction_configured=True)
    assert vm.state == 'U4' and vm.state_text == (
        'Partial unified result: raw-missing. Missing evidence is unknown, not disagreement.')
    vm = load(stale, extraction_configured=True, changed_inputs=('manual_digest', 'sources'))
    assert vm.state == 'U6' and vm.stale_reason.startswith('a manual correction')
    assert vm.state_text == ('The unified result is stale: a manual correction changed the inputs; the stored engine '
                             'results changed. It is shown for reference only.')
    both = load(stale_partial, extraction_configured=True)           # U6 outranks U4, which stays visible beneath it
    assert both.state == 'U6' and [b.split(':')[0] for b in both.banners] == ['The unified result is stale',
                                                                             'Partial unified result']
    assert rm.STALE_FALLBACK in both.state_text                       # no named input: the fallback reason
    # U5 outranks everything: an owner-side error, an unusable pointer
    assert load(stale, error='PT-UNIFIED-STORE: enrichment-unreadable').state == 'U5'
    unusable = load(store.LoadedResult('invalid', 'manifest-hash-mismatch'))
    assert unusable.state == 'U5' and unusable.rows == () and unusable.error.startswith('PT-UNIFIED-STORE')
    assert unusable.state_text == (
        'The unified result could not be produced: PT-UNIFIED-STORE: The stored unified result is unusable '
        '[manifest-hash-mismatch]. Earlier results and the primary Ghidriff results are unchanged.')
    # U7 is a notice for a result without ProgramIR, not a state, and only while extraction is not configured
    assert load(ok).banners == (rm.STATE_TEXT['U7'],) and load(ok).state == 'U3'
    assert load(ok, extraction_configured=True).banners == ()
    # U2 comes from the controller's progress, U8 from the filtered count
    assert rm.progress_text('extract older', 3, 10) == 'Unified analysis: extract older 3/10'
    assert rm.progress_text('ingest', 0, None) == 'Unified analysis: ingest (no counts available)'
    assert rm.progress_model(rm.UnifiedLoadRequest('p'), 'match', 1, 2).state == 'U2'
    ready = load(ok)
    assert rm.display_state(ready, 100_000) == ('U3', ready.state_text)
    assert rm.display_state(ready, 100_001) == ('U8', 'Too many rows to display (100,001). Narrow the filter.')


def test_stale_reason_names_each_changed_input():
    assert rm.stale_reason_text(['manual_digest']) == 'a manual correction changed the inputs'
    assert rm.stale_reason_text(['config_digest', 'bogus']) == 'the engine configuration changed'
    assert rm.stale_reason_text([]) == rm.stale_reason_text(['bogus']) == rm.STALE_FALLBACK


def test_load_never_raises_for_data_problems(tmp_path):
    def fresh(name):
        return publish(tmp_path / name, [pair('a', 0x1000), pair('b', 0x2000)])

    truncated = fresh('truncated')
    part = truncated.directory / 'rows.jsonl.gz'
    part.write_bytes(part.read_bytes()[:-9])
    vm = load(truncated)
    assert vm.state == 'U5' and vm.rows == () and 'PT-UNIFIED-STORE' in vm.error and 'part-' in vm.error
    garbage = fresh('garbage')
    (garbage.directory / 'facts.jsonl.gz').write_bytes(b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff' + b'\xff' * 64)
    assert load(garbage).state == 'U5'
    newer = fresh('newer')
    (newer.directory / 'rows.jsonl.gz').write_bytes(gzip.compress(b'{"contract":"unified-match/2"}\n'))
    vm = load(newer)
    assert vm.state == 'U5' and 'PT-UNIFIED-STALE' in vm.error and 'newer-contract' in vm.error
    wrong_id = fresh('wrongid')
    lie = pair('a', 0x1000).model_copy(update={'row_id': '0' * 64})
    (wrong_id.directory / 'rows.jsonl.gz').write_bytes(gzip.compress(store.dump_line(lie)))
    assert load(wrong_id).state == 'U5'
    missing = fresh('missing')
    (missing.directory / 'rows.jsonl.gz').unlink()
    assert load(missing).state == 'U5'


def test_cancel_raises_cancelled_and_nothing_else(tmp_path):
    loaded = publish(tmp_path / 'cancel', [pair('a', 0x1000)])
    with pytest.raises(rm.Cancelled):
        rm.load_unified(request(loaded), lambda: True)
    assert rm.load_unified(request(loaded), lambda: False).state == 'U3'


# --- default filter, collapse count (U-03) ---------------------------------------------------------------------------------


def test_filter_rows_defaults_hide_cosmetic_with_count(tmp_path):
    vm = load(group_fixture(tmp_path))
    assert len(vm.rows) == 13 and vm.counts['hidden'] == 2          # unchanged, and cosmetic with a structural proof
    default = [vm.rows[i].function_label for i in rm.filter_rows(vm.rows)]
    assert len(default) == 11 and 'cosmetic-addr' not in default and 'unchanged' not in default
    assert 'pseudo' in default                                       # decompiler-relative cosmetic stays listed
    assert 'contested-unchanged' in default                          # a contest is never collapsed
    assert '2 cosmetic/unchanged hidden' in vm.state_text and '2 cosmetic/unchanged hidden' in rm.summary_text(vm)
    assert '2 cosmetic/unchanged hidden' not in rm.summary_text(vm, show_collapsed=True)
    assert len(rm.filter_rows(vm.rows, show_collapsed=True)) == 13
    # asking for a materiality always lists it, collapsed or not
    cosmetic = rm.filter_rows(vm.rows, materialities=['cosmetic'])
    assert sorted(vm.rows[i].function_label for i in cosmetic) == ['cosmetic-addr', 'pseudo']
    unchanged = rm.filter_rows(vm.rows, materialities=['unchanged'])
    assert [vm.rows[i].function_label for i in unchanged] == ['contested-unchanged', 'unchanged']
    assert rm.filter_rows(vm.rows, materialities=[]) == [] and rm.filter_rows(vm.rows, decisions=[]) == []


def test_filters_combine_and_search_takes_names_and_hex(tmp_path):
    vm = load(group_fixture(tmp_path), extraction_configured=True)
    at = {r.function_label: i for i, r in enumerate(vm.rows)}
    assert rm.filter_rows(vm.rows, decisions=['older-only', 'newer-only']) == [at['older-only'], at['newer-only']]
    assert rm.filter_rows(vm.rows, classes=['callee']) == [at['material']]
    assert rm.filter_rows(vm.rows, classes=['callee', 'constant']) == [at['material'], at['review']]
    assert rm.filter_rows(vm.rows, decisions=['matched'], classes=['constant']) == [at['review']]
    assert rm.filter_rows(vm.rows, sources=['ghidriff'], search='REVIEW') == [at['review']]
    assert rm.filter_rows(vm.rows, sources=['bindiff']) == [at['contested'], at['contested-unchanged']]
    assert rm.filter_rows(vm.rows, sources=['rz-diff']) == []
    for query in (f'0x{base(2):x}', f'{base(2):x}', f'0X{base(2):X}'):
        assert rm.filter_rows(vm.rows, search=query) == [at['review']]
    assert rm.filter_rows(vm.rows, search='no-such-name') == []


# --- order (07 s7, 05 s2.6, F16, F17) -----------------------------------------------------------------------------------


def test_sort_order_contested_first_then_severity(tmp_path):
    vm = load(group_fixture(tmp_path))
    assert labels(vm) == EXPECTED_GROUP_ORDER
    assert [r.sort_keys[rm.KEY_GROUP] for r in vm.rows] == [0, 0, 1, 2, 3, 4, 4, 4, 5, 5, 6, 7, 8]
    assert rm.GROUP_NAMES[0] == 'contested' and len(rm.GROUP_NAMES) == 9

    # inside a group: the severity list of 05 s2.6, most severe first; the rva only breaks ties
    levels = [('callee', 'call-added', 'call-removed'), ('condition', 'comparison'), ('constant@test',),
              ('struct-offset',), ('data-ref',), ('block-added', 'block-removed'), ('eh',), ('constant',), ('cfg',),
              ('string',), ('unknown',), ('frame',), ('size-only',), ('refcount-only',), ('address-only',),
              ('register-only',), ('name-only',), ('layout-only',)]
    rows, facts, expected = [], [], []
    for rank, level in enumerate(levels):
        for i, cls in enumerate(level):
            real = 'constant' if cls == 'constant@test' else cls
            old, new = ('cmp esi, 0x100', 'cmp esi, 0x200') if cls == 'constant@test' else ('0x100', '0x200')
            row, fact = review_pair(cls, 0x20000 - 0x400 * rank + 0x10 * i, real, old, new)
            rows.append(row)
            facts.append(fact)
            expected.append(cls)
    vm = load(publish(tmp_path / 'severity', rows, facts))
    ranks = [r.sort_keys[rm.KEY_SEVERITY] for r in vm.rows]
    assert labels(vm) == expected and ranks == sorted(ranks) and len(set(ranks)) == len(levels)


def test_library_rows_ordered_last_never_hidden(tmp_path):
    plain = [review_pair(f'first-party-{i}', 0x2000 + 0x100 * i) for i in range(2)]
    library, library_facts = review_pair('library-fn', 0x1000, 'callee', None, 'f', flags=['library'])
    lib_contest = contested_row(0x500, 0x580, 'lib-contest').model_copy(update={'flags': ('library',)})
    first_contest = contested_row(0x9000, 0x9080, 'first-contest')
    rows = [*(r for r, _ in plain), library, lib_contest, first_contest]
    vm = load(publish(tmp_path / 'library', rows, [*(f for _, f in plain), library_facts]))
    assert labels(vm) == ['first-contest', 'lib-contest', 'first-party-0', 'first-party-1', 'library-fn']
    assert 'library' in vm.rows[1].flags and 'library' in vm.rows[-1].flags
    assert len(rm.filter_rows(vm.rows)) == 5                          # tag and order only, never a filter


def test_trace_arg_constant_ordered_last_not_hidden(tmp_path):
    cases = [review_pair('trace-constant', 0x1000, hints=['trace-arg']), review_pair('other-constant', 0x2000),
             review_pair('cfg-change', 0x3000, 'cfg'), review_pair('name-change', 0x4000, 'name-only')]
    vm = load(publish(tmp_path / 'trace', [r for r, _ in cases], [f for _, f in cases]))
    assert labels(vm) == ['other-constant', 'cfg-change', 'name-change', 'trace-constant']   # last inside its verdict
    assert len(rm.filter_rows(vm.rows)) == 4


def test_attention_order_then_rva_inside_equal_severity(tmp_path):
    cases = [review_pair(f'm{i}', 0x1000 + 0x100 * i, match_id=f'm-{i}') for i in range(4)]
    loaded = publish(tmp_path / 'attention', [r for r, _ in cases], [f for _, f in cases])
    assert labels(load(loaded)) == ['m0', 'm1', 'm2', 'm3']                                 # no attention: rva
    assert labels(load(loaded, attention={'m-3': 1, 'm-2': 2})) == ['m3', 'm2', 'm0', 'm1']  # read-only order first


def test_order_is_independent_of_the_stored_order(tmp_path):
    cases = [review_pair(f'f{i}', 0x1000 + 0x100 * i) for i in range(6)]
    rows, facts = [r for r, _ in cases], [f for _, f in cases]
    forward = publish(tmp_path / 'fwd', rows, facts, keep_order=True)
    backward = publish(tmp_path / 'bwd', list(reversed(rows)), list(reversed(facts)), keep_order=True)
    assert [r.row_id for r in load(forward).rows] == [r.row_id for r in load(backward).rows]
    assert labels(load(backward)) == [f'f{i}' for i in range(6)]


def test_sort_rows_by_column_is_stable_with_none_last(tmp_path):
    def row_with(i, similarity):
        o, n = 0x1000 + 0x100 * i, 0x1080 + 0x100 * i
        atoms = [atom(older=o, newer=n)]
        if similarity:
            atoms.append(atom('bindiff', 'name hash matching', older=o, newer=n, native=[('similarity', similarity)]))
        return make_row([(o, f'f{i}')], [(n, f'f{i}')], atoms=atoms)
    rows = [row_with(i, sim) for i, sim in enumerate(['0.5', None, '0.9', '0.5'])]
    vm = load(publish(tmp_path / 'sortcol', rows, sources=[source_ref('ghidriff'), source_ref('bindiff')]))
    everything = list(range(len(vm.rows)))

    def order(column, **kw):
        return [vm.rows[i].function_label for i in rm.sort_rows(vm.rows, everything, rm.column_sort_key(vm, column), **kw)]
    assert order('source:bindiff') == ['f0', 'f3', 'f2', 'f1']                      # f1 has no record: last
    assert order('source:bindiff', descending=True) == ['f2', 'f0', 'f3', 'f1']     # still last, ties keep their order
    assert order('function', descending=True) == ['f3', 'f2', 'f1', 'f0']
    assert order('decision') == ['f0', 'f1', 'f2', 'f3'] and order('change') == ['f0', 'f1', 'f2', 'f3']
    assert order('source:nonexistent') == ['f0', 'f1', 'f2', 'f3']
    assert rm.sort_rows(vm.rows, [3, 1], rm.column_sort_key(vm, 'default')) == [1, 3]


def test_change_column_sorts_by_materiality_then_severity(tmp_path):
    cases = [review_pair('r-constant', 0x1000), review_pair('r-cfg', 0x2000, 'cfg'),
             review_pair('r-callee', 0x3000, 'callee', None, 'f'),
             material({'older': [(0x4000, 'm-callee')], 'newer': [(0x4080, 'm-callee')]})]
    plain = pair('u-plain', 0x5000)
    vm = load(publish(tmp_path / 'changecol', [plain, *(r for r, _ in cases)], [f for _, f in cases]))
    backwards = list(reversed(range(len(vm.rows))))          # not the default order: the key itself must decide
    ordered = rm.sort_rows(vm.rows, backwards, rm.column_sort_key(vm, 'change'))
    assert [vm.rows[i].function_label for i in ordered] == ['m-callee', 'r-callee', 'r-constant', 'r-cfg', 'u-plain']


def test_a_contested_row_is_first_whatever_its_change(tmp_path):
    rows, facts = [], []
    for name, rva, change, args in (('c-material', 0x9000, 'material', {'second': 'C6', 'deltas': [delta('callee')]}),
                                    ('c-review', 0x9100, 'review', {'deltas': [delta('constant', channel='C5')]}),
                                    ('c-pseudo', 0x9200, 'cosmetic', {'proof': 'COS-PSEUDO/1'})):
        row = contested_row(rva, rva + 0x80, name, materiality=change)
        rows.append(row)
        facts.append(make_facts(row, change, **args))
    clean_row, clean_fact = material({'older': [(0x1000, 'clean')], 'newer': [(0x1080, 'clean')]})
    vm = load(publish(tmp_path / 'contest-first', [*rows, clean_row], [*facts, clean_fact]))
    assert labels(vm) == ['c-material', 'c-review', 'c-pseudo', 'clean']
    assert [r.sort_keys[rm.KEY_GROUP] for r in vm.rows] == [0, 0, 0, 1]


# --- cells ----------------------------------------------------------------------------------------------------------------


def three_source_rows():
    alpha = make_row([(0x1000, 'alpha')], [(0x1080, 'alpha')], atoms=[
        atom(native=[('ratio', '0.9'), ('match types', 'ExactBytesFunctionHasher, SymbolsHash')]),
        atom('bindiff', 'name hash matching', native=[('similarity', '0.97'), ('confidence', '0.99')]),
        atom('rz-diff', 'levenshtein-bytes', tier='W', cls='E-BODY', native=[('similarity', '0.88'), ('type', 'PARTIAL')])])
    return [alpha, contested_row(0x2000, 0x2080, 'beta')]   # BinDiff pairs beta's older function with another newer one


def test_cells_never_combine_sources(tmp_path):
    loaded = publish(tmp_path / 'cells', three_source_rows(), sources=[
        source_ref('ghidriff'), source_ref('bindiff', '8.0'), source_ref('rz-diff', '0.9.1')])
    vm = load(loaded)
    assert [s.source for s in vm.sources] == ['ghidriff', 'bindiff', 'rz-diff']       # registry display order
    assert [s.version for s in vm.sources] == ['1', '8.0', '0.9.1']
    assert [(s.display, s.unit_caption) for s in vm.sources] == [
        ('Ghidriff', 'match type (raw)'), ('BinDiff', 'similarity / algorithm'), ('rz-diff', 'byte similarity')]
    alpha, beta = (next(r for r in vm.rows if r.function_label == n) for n in ('alpha', 'beta'))
    ghidriff, bindiff, rzdiff = alpha.cells
    assert ghidriff.text == 'SymbolsHash (+1)' and ghidriff.sort_key is None
    assert bindiff.text == 'sim 0.97  algo name hash matching' and bindiff.sort_key == 970
    assert rzdiff.text == 'byte sim 0.88' and rzdiff.sort_key == 880
    for cell, foreign in ((ghidriff, ('0.97', '0.88', '0.9')), (bindiff, ('0.88', 'SymbolsHash', '0.9 ')),
                          (rzdiff, ('0.97', 'SymbolsHash', 'name hash'))):
        assert not any(value in cell.text for value in foreign), cell
    assert bindiff.spoken == 'BinDiff similarity 0.97, algorithm name hash matching'
    assert rzdiff.spoken == 'rz-diff byte similarity 0.88' and ghidriff.spoken == 'Ghidriff match type SymbolsHash (+1)'
    assert alpha.source_ids == {'ghidriff', 'bindiff', 'rz-diff'} and beta.source_ids == {'ghidriff', 'bindiff'}
    # missing is unknown, not a vote: no record, and a pairing elsewhere is named, never merged into a value
    assert [(c.kind, c.text) for c in beta.cells] == [('value', 'SymbolsHash'), ('pairs-elsewhere', 'pairs elsewhere'),
                                                      ('no-record', 'no record')]
    assert beta.cells[1].sort_key is None and beta.cells[2].sort_key is None
    field_names = {f.name for cls in (rm.UnifiedRowView, rm.UnifiedViewModel, rm.SourceCell) for f in fields(cls)}
    assert not any(word in name for name in field_names for word in ('combined', 'average', 'overall', 'consensus',
                                                                   'score', 'confidence', 'probab'))
    assert [c.title for c in rm.columns(vm)] == ['Function', 'Decision', 'Change', 'Ghidriff', 'BinDiff', 'rz-diff']
    assert [rm.cell_text(alpha, i) for i in range(6)] == [
        'alpha  0x1000 > 0x1080', '[=] Matched', 'Unknown', 'SymbolsHash (+1)', 'sim 0.97  algo name hash matching',
        'byte sim 0.88']
    assert rm.cell_spoken(beta, 1) == 'Decision: Contested' and rm.cell_spoken(beta, 2) == 'Change: Unknown'
    assert 'Function beta' in rm.cell_spoken(beta, 0) and rm.cell_spoken(alpha, 4) == bindiff.spoken


def test_a_source_that_agrees_and_also_pairs_elsewhere_says_both(tmp_path):
    row = make_row([(0x1000, 'f')], [(0x1080, 'f')], decision='contested', atoms=[
        atom(), atom('bindiff', 'hash matching', native=[('similarity', '1.0')]),
        atom('bindiff', 'alt-rank-2', tier='C', cls='E-UNKNOWN', newer=0x1180)],
        contest=Contest(strength='weak', against=(2,)), support=[Support(component='K1', tier='A', atom_index=0)])
    vm = load(publish(tmp_path / 'both', [row], sources=[source_ref('ghidriff'), source_ref('bindiff')]))
    cell = vm.rows[0].cells[1]
    assert cell.kind == 'value' and cell.text == 'sim 1.0  algo hash matching (also pairs elsewhere)'
    assert 'also pairs elsewhere' in cell.spoken


def test_pass_cells_show_pass_id_and_tier_and_unknown_sources_render_generically(tmp_path):
    row = make_row([(0x1000, 'f')], [(0x1080, 'f')], atoms=[
        atom('pt-ladder', 'P03-name-exact'), atom('pt-bytes', 'P05-masked-exact', cls='E-BODY'),
        atom('manual', 'manual-correction', tier='M', cls='E-MANUAL'), atom('newengine', 'future-pass', tier='B')],
        support=[Support(component='K1', tier='M', atom_index=2)])
    vm = load(publish(tmp_path / 'passes', [row]))
    assert [s.source for s in vm.sources] == ['pt-ladder', 'pt-bytes', 'manual', 'newengine']   # unknown ids last
    assert [c.text for c in vm.rows[0].cells] == ['P03 name-exact (A)', 'P05 masked-exact (A)', 'correction',
                                                  'future-pass (B)']
    unknown = vm.sources[-1]
    assert (unknown.known, unknown.display, unknown.tooltip_id) == (False, 'newengine (unknown source)',
                                                                     'unified.source.unknown')
    assert unknown.tooltip_id in rm.TOOLTIP_IDS and all(s.known for s in vm.sources[:3])
    assert vm.rows[0].tier == 'M'


def test_unit_words_follow_each_source(tmp_path):
    row = make_row([(0x1000, 'f')], [(0x1080, 'f')], atoms=[
        atom('diaphora', 'best', tier='B', native=[('category', 'best'), ('ratio', '1.01')]),
        atom('bindiff', 'name hash matching')], support=[Support(component='K1', tier='A', atom_index=1)])
    vm = load(publish(tmp_path / 'units', [row]))
    assert [s.source for s in vm.sources] == ['bindiff', 'diaphora']
    assert [c.text for c in vm.rows[0].cells] == ['algo name hash matching', 'best 1.01']
    assert vm.rows[0].cells[0].sort_key is None and vm.rows[0].cells[1].sort_key == 1010
    assert 'similarity unknown' in vm.rows[0].cells[0].spoken       # an absent similarity is unknown, never zero


def test_similarity_orders_a_column_only_when_it_is_a_plain_number(tmp_path):
    cases = {'0.5': 500, '1.0': 1000, '1000': 1_000_000, '': None, 'nan': None, '-0.5': None, '1e999': None,
             'abc': None, '0x10': None}
    rows = []
    for i, text in enumerate(cases):
        o, n = 0x1000 + 0x100 * i, 0x1080 + 0x100 * i
        native = [('similarity', text)] if text else []
        rows.append(make_row([(o, f'f{i}')], [(n, f'f{i}')], atoms=[
            atom('bindiff', 'name hash matching', older=o, newer=n, native=native)]))
    vm = load(publish(tmp_path / 'similarity', rows))
    assert [r.cells[0].sort_key for r in vm.rows] == list(cases.values())


def test_support_lines_follow_the_component_numbers(tmp_path):
    row = make_row([(0x1000, 'f')], [(0x1080, 'f')], atoms=[atom(), atom('pt-bytes', 'P05-masked-exact', cls='E-BODY'),
                                                            atom('bindiff', 'name hash matching')],
                   support=[Support(component='K10', tier='A', atom_index=2),
                            Support(component='K2', tier='A', atom_index=1),
                            Support(component='K1', tier='A', atom_index=0)])
    vm = load(publish(tmp_path / 'supports', [row]))
    text = rm.row_detail(vm, vm.rows[0])
    assert text.index('K1: ghidriff') < text.index('K2: pt-bytes') < text.index('K10: bindiff')


# --- edit groups (F10) ----------------------------------------------------------------------------------------------------------


def test_edit_group_never_removes_rows(tmp_path):
    cases = []
    for i in range(4):          # the same added call in four functions: one edit group
        cases.append(material({'older': [(0x1000 + 0x100 * i, f'caller{i}')], 'newer': [(0x1080 + 0x100 * i, f'caller{i}')]},
                              new='report_invalid_index'))
    for i in range(2):          # only two rows share this change: below the threshold
        cases.append(material({'older': [(0x4000 + 0x100 * i, f'pair{i}')], 'newer': [(0x4080 + 0x100 * i, f'pair{i}')]},
                              new='other_call'))
    cases.append(material({'older': [(0x6000, 'single')], 'newer': [(0x6080, 'single')]}, new='unique_call'))
    vm = load(publish(tmp_path / 'edits', [r for r, _ in cases], [f for _, f in cases]))
    assert len(vm.rows) == 7 and len(rm.filter_rows(vm.rows)) == 7                 # a group is a view: nothing is removed
    assert [(g.group_id, g.size, g.summary) for g in vm.edit_groups] == [(1, 4, 'callee: - -> report_invalid_index')]
    grouped = sorted(r.function_label for r in vm.rows if r.edit_group == 1)
    assert grouped == ['caller0', 'caller1', 'caller2', 'caller3']
    assert all(r.edit_group == 0 for r in vm.rows if r.function_label not in grouped)
    assert sorted(vm.rows[i].function_label for i in rm.filter_rows(vm.rows, edit_group=1)) == grouped
    detail = rm.row_detail(vm, next(r for r in vm.rows if r.function_label == 'caller0'))
    assert 'The same change appears in 4 rows (edit group 1)' in detail and 'Every row stays listed' in detail
    assert 'edit group' not in rm.row_detail(vm, next(r for r in vm.rows if r.function_label == 'single'))


# --- verbose text -------------------------------------------------------------------------------------------------------------


def rich_result(tmp_path):
    row, fact = material({'older': [(0x1000, 'alpha')], 'newer': [(0x1080, 'alpha')]}, new='report_invalid_index',
                         match_id='m-1')
    row = row.model_copy(update={'hints': ('ghidriff-diff-types:address,code',)})
    return publish(tmp_path / 'rich', [row, contested_row(0x2000, 0x2080, 'beta'), pair('gamma', 0x3000)], [fact],
                   sources=[source_ref('ghidriff'), source_ref('bindiff', '8.0')])


def test_row_detail_has_the_fixed_sections_in_order(tmp_path):
    loaded = rich_result(tmp_path)
    vm = load(loaded)
    alpha = next(r for r in vm.rows if r.function_label == 'alpha')
    text = rm.row_detail(vm, alpha)
    headers = ['Function: ', 'Decision: ', 'Support by component:', 'Evidence classes (', 'Contest:', 'Atoms (1):',
               'Change facts:', 'Limitations:', 'Provenance:']
    positions = [text.index(h) for h in headers]
    assert positions == sorted(positions) and text.endswith(rt.FOOTER)
    assert 'K1: ghidriff SymbolsHash tier A (atom 0)' in text and 'E-NAME (names): 1 atom(s) from ghidriff' in text
    assert 'verdict material, second channel C6' in text
    assert 'delta callee (C4) 0x1000 -> 0x1080 - -> report_invalid_index' in text
    assert 'Change: Material; classes: callee' in text and 'Hint: ghidriff-diff-types:address,code' in text
    assert '- ir-not-extracted' in text and 'ghidriff 1 (external process, GPL-3.0; JSON consumed as data)' in text
    assert 'ProgramIR: none (stored engine outputs only)' in text and 'display level: ordinal' in text
    contested = rm.row_detail(vm, next(r for r in vm.rows if r.function_label == 'beta'))
    assert 'Strong contest: 1 piece(s) of evidence pair an endpoint differently.' in contested
    assert 'strong (atoms against: 1)' in contested
    assert '[1] bindiff name hash matching tier A E-NAME 1:1 0x2000 -> 0x2180' in contested
    assert 'none (this row gets no change facts)' in contested
    stale = load(store.LoadedResult('stale', 'guard-moved', None, None, loaded.manifest, loaded.directory))
    assert 'This result is stale' in rm.row_detail(stale, stale.rows[0])


def test_evidence_breakdown_counts_distinct_classes(tmp_path):
    row = make_row([(0x1000, 'f')], [(0x1080, 'f')], atoms=[
        atom(), atom('pt-ladder', 'P03-name-exact'), atom('bindiff', 'edges flow', cls='E-CFG'),
        atom('rz-diff', 'levenshtein-bytes', tier='W', cls='E-BODY'),
        atom('bindiff', 'alt', tier='C', cls='E-CALL', newer=0x1180)])               # off the pair: not counted
    assert [(b.cls, b.atoms, b.sources, b.best_tier) for b in rt.evidence_breakdown(row)] == [
        ('E-NAME', 2, ('ghidriff', 'pt-ladder'), 'A'), ('E-BODY', 1, ('rz-diff',), 'W'), ('E-CFG', 1, ('bindiff',), 'A')]
    vm = load(publish(tmp_path / 'classes', [row, pair('other', 0x5000)]))
    assert dict(vm.evidence_classes) == {'E-NAME': 2, 'E-BODY': 1, 'E-CFG': 1}     # rows per class, never a score
    assert rm.evidence_summary(vm) == ('Rows by evidence class: E-NAME (names) 2 - E-BODY (code bytes and '
                                       'instructions) 1 - E-CFG (control-flow shape) 1')
    assert rm.evidence_summary(rm.load_unified(rm.UnifiedLoadRequest('p'))) == 'Rows by evidence class: none'


def test_explain_context_is_a_bounded_plain_text_fragment(tmp_path):
    row = pair('f', 0x1000, materiality='review', classes=['constant'])
    many = [delta('constant', old=f'{i}', new=f'{i + 1}', channel='C5') for i in range(12)]
    vm = load(publish(tmp_path / 'context', [row], [make_facts(row, 'review', deltas=many)]))
    fragment = rm.explain_context(vm, vm.rows[0])
    assert (fragment.kind, fragment.row_id) == ('unified-row', row.row_id) and len(fragment.text) <= rt.CONTEXT_CAP
    assert fragment.omitted == ('4 deltas not included',) and fragment.text.count('delta constant') == rt.CONTEXT_DELTAS
    assert 'derived, rule-based and uncalibrated' in fragment.text and '\n\n' not in fragment.text
    assert_no_banned(fragment.title + fragment.text)
    plain = load(publish(tmp_path / 'context2', [pair('g', 0x9000)]))
    assert rm.explain_context(plain, plain.rows[0]).omitted == ('change facts: none for this row',)
    assert rm.explain_context(rm.load_unified(rm.UnifiedLoadRequest('p')), plain.rows[0]) is None


def test_provenance_block_deterministic_and_capped(tmp_path):
    rows = [pair(f'fn{i:03d}', 0x1000 + 0x100 * i) for i in range(300)]
    vm = load(publish(tmp_path / 'prov', rows, sources=[source_ref('ghidriff')]))
    block = rm.provenance_block(vm, vm.rows[:2])
    assert block == rm.provenance_block(vm, vm.rows[:2]) and '\r' not in block
    lines = block.splitlines()
    assert lines[0] == rt.PROVENANCE_HEADER and lines[-1] == rt.PROVENANCE_FOOTER
    assert f'Result: {vm.result_id}' in block and 'STALE: no' in block and vm.rows[0].row_id in block
    assert 'Older SHA-256: ' + 'a' * 64 in block and 'Sources: ghidriff 1' in block and '- ir-not-extracted' in block
    big = rm.provenance_block(vm, vm.rows)
    shown = big.count('\nRow: ')
    assert len(big) <= 16 * 1024 and 0 < shown <= 200 and big.splitlines()[-1] == rt.PROVENANCE_FOOTER
    assert f'({300 - shown} more rows omitted)' in big
    assert 'Sources: ghidriff 1' in big and '- ir-not-extracted' in big      # identity and limitations always survive
    stale = load(store.LoadedResult('stale', 'guard-moved', None, None, vm.manifest, tmp_path / 'prov'),
                 changed_inputs=['manual_digest'])
    assert 'STALE: yes (a manual correction changed the inputs)' in rm.provenance_block(stale, stale.rows[:1])
    assert_no_banned(big)


def test_provenance_block_stays_capped_when_the_identity_alone_is_large(tmp_path):
    limitations = tuple(f'{i:02d}' + 'x' * 190 for i in range(64))
    sources = [source_ref(f'src{i:02d}', 'v' * 60) for i in range(64)]
    vm = load(publish(tmp_path / 'huge', [pair('f', 0x1000)], limitations=limitations, sources=sources))
    block = rm.provenance_block(vm, vm.rows)
    assert len(block) <= 16 * 1024 and block.endswith('(truncated)')
    assert block.splitlines()[0] == rt.PROVENANCE_HEADER and '\r' not in block


def test_clean_is_one_line_bounded_plain_text():
    assert rt.clean(None) == '' and rt.clean(5) == '5' and rt.clean('plain') == 'plain'
    assert rt.clean('a\nb\tc') == 'a b c'
    assert rt.clean('<b>x</b> {0} %s &lt;') == '<b>x</b> {0} %s &lt;'            # plain text stays as typed
    assert rt.clean('\x1b[31m') == '[31m' and rt.clean('rev' + chr(0x202E) + 'x' + chr(0x2066)) == 'revx'
    assert rt.clean('a\xa0b') == 'a\xa0b'                                      # printable-looking text is not touched
    assert len(rt.clean('y' * 500)) == 200 and rt.clean('x' * 300, 20) == 'x' * 17 + '...'


def test_side_text_names_group_sides_and_missing_sides():
    function = SideRef(rva=0x10, name='f', kind='function')
    assert rt.side_text(()) == '-' and rt.side_text((function,)) == '0x10 f'
    assert rt.side_text((function, SideRef(rva=0x20, name=None, kind='thunk'))) == '0x10 f (+1)'
    assert rt.side_text((SideRef(rva=0x10, name=None, kind='function'),)) == '0x10'


def test_header_text_names_absent_sources_and_staleness(tmp_path):
    loaded = rich_result(tmp_path)
    header = rm.header_text(load(loaded, extraction_configured=True))
    assert header.startswith('Unified: ude/1, run ') and ' UTC, stale: no | Sources: Ghidriff 1, BinDiff 8.0' in header
    assert header.endswith('| Not present: rz-diff, Diaphora, PatchTrace ladder, PatchTrace bytes, Analyst')
    stale = store.LoadedResult('stale', 'guard-moved', None, None, loaded.manifest, loaded.directory)
    assert ', stale: yes |' in rm.header_text(load(stale))
    assert rm.header_text(rm.load_unified(rm.UnifiedLoadRequest('p'))) == ''


def test_rows_tsv_has_a_header_and_a_cap(tmp_path):
    vm = load(rich_result(tmp_path))
    lines = rm.rows_tsv(vm, vm.rows).split('\n')
    assert lines[0] == 'Function\tDecision\tChange\tGhidriff\tBinDiff' and len(lines) == 4
    assert all(line.count('\t') == 4 for line in lines)
    big = rm.rows_tsv(vm, vm.rows * 1000)
    assert len(big) <= 16 * 1024 and big.endswith('(truncated)')


def test_detail_degrades_to_a_sentence_when_the_sidecar_is_damaged(tmp_path):
    loaded = rich_result(tmp_path)
    vm = load(loaded)
    part = loaded.directory / 'rows.jsonl.gz'
    part.write_bytes(part.read_bytes()[:-9])
    assert rm.row_detail(vm, vm.rows[0]).startswith('Details could not be read: PT-UNIFIED-STORE')
    assert rm.provenance_block(vm, vm.rows[:1]).startswith('Provenance could not be read: PT-UNIFIED-STORE')
    assert rm.explain_context(vm, vm.rows[0]) is None
    empty = rm.load_unified(rm.UnifiedLoadRequest('p'))
    assert rm.row_detail(empty, vm.rows[0]) == 'Details are not available for this result.'
    assert rm.provenance_block(empty, []) == '' and rm.records_for(empty, vm.rows) == {}


def test_sidecar_records_find_and_get(tmp_path):
    loaded = rich_result(tmp_path)
    records = rt.SidecarRecords(loaded.directory, loaded.manifest)
    ids = [r.row_id for r in load(loaded).rows]
    assert records.find(ids[0][:10]) == [ids[0]] and records.find(ids[0]) == [ids[0]]
    assert len(records.find('')) == 2 and sorted(records.find('', None)) == sorted(ids)   # '' is a prefix of every id
    assert records.find('zz') == [] and records.find('f' * 65) == [] and records.find('0' * 64) == []
    found = records.get(ids)
    assert set(found) == set(ids) and sum(1 for r in found.values() if r.facts is not None) == 1
    assert records.get(['0' * 64]) == {} and records.get([]) == {}
    with pytest.raises(UnifiedError):
        rt.SidecarRecords(loaded.directory, loaded.manifest.model_copy(update={'parts': ()})).get(ids)


def test_a_name_that_looks_like_the_row_id_key_does_not_confuse_the_scan(tmp_path):
    hostile = '"row_id":"' + '0' * 64
    row = pair(hostile, 0x1000)
    other = pair('other', 0x2000)
    loaded = publish(tmp_path / 'marker', [row, other])
    records = rt.SidecarRecords(loaded.directory, loaded.manifest)
    assert records.find('0' * 8) == []                         # the name is escaped in the line, so it never matches
    assert set(records.get([row.row_id])) == {row.row_id}
    assert records.get([row.row_id])[row.row_id].match.older[0].name == hostile


# --- text safety ----------------------------------------------------------------------------------------------------------------------


def one_line_strings(vm):
    """Every string a person reads in one line: status, banners, labels, cells."""
    yield vm.state_text
    yield from vm.banners
    yield from vm.warnings
    yield from vm.absent_sources
    yield rm.summary_text(vm)
    yield rm.header_text(vm)
    yield rm.evidence_summary(vm)
    for s in vm.sources:
        yield from (s.display, s.unit_caption, s.version)
    for g in vm.edit_groups:
        yield g.summary
    for r in vm.rows:
        yield from (r.function_label, r.address_label, r.decision_text, r.materiality_text, r.change_text, r.search_key,
                    r.glyph, *r.classes)
        for c in r.cells:
            yield from (c.text, c.spoken)


def multi_line_strings(vm):
    """The verbose texts: detail per row, the clipboard blocks and the tab-separated copy."""
    for r in vm.rows:
        yield rm.row_detail(vm, r)
        yield rm.explain_context(vm, r).text
    yield rm.provenance_block(vm, vm.rows)
    yield rm.rows_tsv(vm, vm.rows)


def test_unified_banned_strings_never_appear(tmp_path):
    texts = [*rm.STATE_TEXT.values(), *rt.DECISION_MEANING.values(), rt.FOOTER, rt.PROVENANCE_HEADER,
             rt.PROVENANCE_FOOTER, *rt.TIER_NAMES.values(), *rt.CLASS_NAMES.values(), *rm.STALE_REASONS.values(),
             *(c.spoken for t in (rm.DECISION_CHIPS, rm.MATERIALITY_CHIPS, rm.TIER_CHIPS) for c in t.values()),
             rm.progress_text('stage', 1, 2)]
    partial = publish(tmp_path / 'p2', [pair('f', 0x1000)], status='partial', limitations=('raw-missing',))
    for loaded in (rich_result(tmp_path), partial, group_fixture(tmp_path)):
        vm = load(loaded)
        texts += [*one_line_strings(vm), *multi_line_strings(vm)]
    assert len(texts) > 150
    for text in texts:
        assert_no_banned(text)


@pytest.mark.parametrize('hostile', HOSTILE, ids=HOSTILE_IDS)
def test_hostile_names_plain_text(tmp_path, hostile):
    """The C6 hostile list: markup stays literal text, controls and bidirectional characters are gone, and nothing is
    interpreted as a format string."""
    row = make_row([(0x1000, hostile)], [(0x1080, hostile + 'x')], atoms=[
        atom(step=hostile, native=[('match types', hostile), ('ratio', hostile)], ref=hostile[:128] or None),
        atom('bindiff', hostile, native=[('similarity', hostile)])], materiality='review', classes=['constant'],
        hints=[hostile])
    fact = make_facts(row, 'review', deltas=[delta('constant', old=hostile, new=hostile, channel='C5')])
    version = hostile.replace('\x1b', '').replace('\u202e', '') or 'v'     # versions are identifiers: rejected, not cleaned
    vm = load(publish(tmp_path / 'hostile', [row], [fact], limitations=(hostile, 'ir-not-extracted'),
                      sources=[source_ref('ghidriff', version)]))
    assert vm.state == 'U3'
    plain = hostile.replace('\x1b', '\ufffd').replace('\u202e', '\ufffd')
    short, long = list(one_line_strings(vm)), list(multi_line_strings(vm))
    for text in short:
        assert not set(text) & (FORBIDDEN_CHARS | {'\n', '\t'}), repr(text[:120])
    for text in long:
        assert not set(text) & FORBIDDEN_CHARS, repr(text[:120])
    assert plain in vm.rows[0].function_label                 # shown as typed, never escaped or interpreted
    assert plain in rm.row_detail(vm, vm.rows[0])


def test_names_written_raw_into_the_sidecar_are_still_plain(tmp_path):
    """02 s9.1: the contract replaces control and bidirectional characters when a stored row is read back, so a
    hostile name that was written without validation never reaches a label either."""
    hostile = 'evil\x1b[31m\u202e\u2066name\r\nnext\x00line'
    row = pair('placeholder', 0x1000)
    raw = row.model_copy(update={'older': tuple(SideRef.model_construct(rva=s.rva, name=hostile, kind=s.kind)
                                                for s in row.older)})
    vm = load(publish(tmp_path / 'raw', [raw]))
    assert vm.state == 'U3'
    assert not set(vm.rows[0].function_label + vm.rows[0].search_key) & (FORBIDDEN_CHARS | {'\n', '\t'})
    assert not set(rm.row_detail(vm, vm.rows[0])) & FORBIDDEN_CHARS


# --- scale (07 s11, 08: first paint, filter and sort at 100,000 rows) ----------------------------------------------------------------


def synthetic_rows(count: int):
    """`count` immutable row views as a load would build them (shared cells and tuples, per-row labels)."""
    ghidriff = rm.SourceCell('ghidriff', 'value', 'SymbolsHash', None, 'Ghidriff match type SymbolsHash')
    bindiff = [rm.SourceCell('bindiff', 'value', f'sim 0.{90 + k}  algo name hash matching', 900 + 10 * k, 'spoken')
               for k in range(10)]
    decisions = ['matched'] * 17 + ['contested', 'tentative', 'older-only']
    changes = ['unknown'] * 14 + ['review'] * 3 + ['unchanged', 'material', 'cosmetic']
    classes = [(), ('constant',), ('callee',), ('address-only',)]
    sources = frozenset({'ghidriff', 'bindiff'})
    rows = []
    for i in range(count):
        decision, change = decisions[i % 20], changes[i % 20]
        chip, word = rm.DECISION_CHIPS[decision], rm.MATERIALITY_CHIPS[change].text
        rows.append(rm.UnifiedRowView(
            f'{i:064x}', f'Function_{i}', f'0x{i:X} > 0x{i + 16:X}', decision, chip.text, chip.glyph, change, word,
            word, classes[i % 4], None, 'A', (), (ghidriff, bindiff[i % 10]), sources, None, 0, change == 'unchanged',
            (i % 9, 0, 0, i % 18, rm.ATTENTION_NONE, i), f'function_{i} {i:x}'))
    return tuple(rows)


def test_filter_and_sort_budget_at_100000_rows():
    """L-35: filter <= 100 ms and sort <= 150 ms at 100,000 rows, with the repo's 5x wall-clock slack."""
    rows = synthetic_rows(rm.DISPLAY_ROW_CAP)
    infos = (rm.SourceInfo('ghidriff', 'Ghidriff', 'u', 't', '1', True), rm.SourceInfo('bindiff', 'BinDiff', 'u', 't', '1', True))
    vm = rm.UnifiedViewModel('p', None, 0, 'U3', '', infos, rows, {}, (), None, 'ordinal')

    def took(fn):
        start = time.perf_counter()
        return fn(), time.perf_counter() - start
    default, t_default = took(lambda: rm.filter_rows(rows))
    searched, t_search = took(lambda: rm.filter_rows(rows, search='function_99999'))
    combined, t_combined = took(lambda: rm.filter_rows(rows, decisions={'matched', 'contested'}, classes={'callee'},
                                                       sources={'bindiff'}))
    assert len(default) == 95_000 and searched == [99_999] and 0 < len(combined) < len(default)
    assert max(t_default, t_search, t_combined) < 0.5, (t_default, t_search, t_combined)
    everything = list(range(len(rows)))

    def best_sort(fn):
        # A single CPU deschedule on a shared Windows runner is not algorithmic cost.
        # Check deterministic output across attempts, then keep the fastest elapsed
        # time as the existing paint budget does below. The 0.75s gate is unchanged.
        samples = [took(fn) for _ in range(3)]
        assert all(order == samples[0][0] for order, _ in samples[1:])
        return samples[0][0], min(elapsed for _, elapsed in samples)

    ordered, t_sort = best_sort(lambda: rm.sort_rows(rows, everything))
    _, t_cell = best_sort(lambda: rm.sort_rows(rows, everything, rm.column_sort_key(vm, 'source:bindiff')))
    _, t_name = best_sort(lambda: rm.sort_rows(rows, everything, rm.column_sort_key(vm, 'function'),
                                               descending=True))
    assert sorted(ordered) == everything
    assert max(t_sort, t_cell, t_name) < 0.75, (t_sort, t_cell, t_name)
    # paint-time access is O(1) and independent of N: 7 x visible cells x 1.2 + 20 calls (GUI plan 8.4)
    def paint():
        return [rm.cell_text(row, column) for row in rows[50_000:50_030] for column in range(5) for _ in range(7)]
    best = min(took(paint)[1] for _ in range(5))      # best of 5: one scheduler hiccup on a shared runner is not O(N)
    assert len(paint()) == 1050 and best < 0.05


def test_load_stays_light_per_row(tmp_path):
    """Rows are kept small (about 1 KiB each) so the display cap of 100,000 rows fits in memory; the heavy records
    are read lazily. Measured over 2,000 real rows."""
    rows = []
    for i in range(2000):
        o, n = 0x1000 + 0x40 * i, 0x1080 + 0x40 * i
        rows.append(make_row([(o, f'Function_{i}')], [(n, f'Function_{i}')], atoms=[
            atom(older=o, newer=n, native=[('ratio', f'0.{i % 100}'), ('match types', 'SymbolsHash')]),
            atom('bindiff', 'name hash matching', older=o, newer=n, native=[('similarity', f'0.{90 + i % 10}')])]))
    loaded = publish(tmp_path / 'light', rows, sources=[source_ref('ghidriff'), source_ref('bindiff')])
    del rows
    tracemalloc.start()
    try:
        vm = load(loaded)
        retained, _ = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert vm.state == 'U3' and len(vm.rows) == 2000
    assert retained / len(vm.rows) < 2048, retained / len(vm.rows)
    assert len({id(c) for r in vm.rows for c in r.cells}) <= 25          # identical cells are shared between rows
    assert len({id(r.source_ids) for r in vm.rows}) == 1


# --- the owner thread: a request from a project ---------------------------------------------------------------------------------------------


def test_request_from_service_follows_the_project(tmp_path):
    root = tmp_path / 'project'
    make_project(root).close()
    service = ProjectService.open(root)
    try:
        first = rm.request_from_service(service)
        assert first.project_id == service.project.id and first.revision == service.project.revision
        assert rm.load_unified(first).state == 'U1'                       # a project, no unified result yet
        pipeline.run_unified(service, UnifiedOptions(isolate=False))
        current = rm.request_from_service(service)
        vm = rm.load_unified(current)
        assert (vm.state, current.changed_inputs, current.run_id) == ('U3', (), vm.manifest.ghidriff_run_id)
        assert vm.counts['rows'] == 6 and vm.banners == (rm.STATE_TEXT['U7'],)
        assert rm.load_unified(rm.request_from_service(service, extraction_configured=True)).banners == ()
        deleted = next(m for m in service.project.matches if m.category == 'removed')
        added = next(m for m in service.project.matches if m.category == 'added')
        service.correct_match(deleted.id, [deleted.older[0].id], [added.newer[0].id], 'modified', 'a correction')
        moved = rm.request_from_service(service)
        vm = rm.load_unified(moved)
        assert vm.state == 'U6' and 'manual_digest' in moved.changed_inputs and vm.revision == service.project.revision
        assert 'a manual correction changed the inputs' in vm.state_text
        assert len(vm.rows) == 6                                          # the stale result is still shown, for reference
    finally:
        service.close()


def test_request_from_service_reports_a_store_failure_as_a_state(tmp_path, monkeypatch):
    root = tmp_path / 'project'
    make_project(root).close()
    service = ProjectService.open(root)
    try:
        def broken(*args, **kwargs):
            raise UnifiedError('PT-UNIFIED-STORE', 'The enrichment store is unreadable', reason='enrichment-unreadable')
        monkeypatch.setattr(pipeline, 'load_current', broken)
        vm = rm.load_unified(rm.request_from_service(service))
        assert vm.state == 'U5'
        assert 'PT-UNIFIED-STORE: The enrichment store is unreadable [enrichment-unreadable]' in vm.state_text
    finally:
        service.close()


def test_a_project_without_a_run_has_no_plan_but_still_answers(tmp_path):
    older, newer = tmp_path / 'o.dll', tmp_path / 'n.dll'
    older.write_bytes(synthetic_pe(0))
    newer.write_bytes(synthetic_pe(1))
    service = ProjectService.create(older, newer, 'no run', tmp_path / 'norun')
    try:
        no_plan = rm.request_from_service(service)
        assert no_plan.run_id is None and rm.load_unified(no_plan).state == 'U1'
    finally:
        service.close()
