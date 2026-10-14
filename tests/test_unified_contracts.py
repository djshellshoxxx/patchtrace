"""SPEC-31 S0a contracts: committed schemas and valid/invalid examples, strictness, invariants, limits, budget.
Synthetic data only; nothing here is live evidence."""
from __future__ import annotations

import ast
import copy
import json
import os
import runpy
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from patchtrace.persistence import strict_json
from patchtrace.unified import contracts as uc
from patchtrace.unified import keys
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget, BudgetExhausted, UnifiedError, UnifiedLimits

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / 'docs' / 'schemas'
EXAMPLES = SCHEMAS / 'unified' / 'examples'
INDEX = json.loads((EXAMPLES / 'index.json').read_text(encoding='utf-8'))
NAMES = sorted(INDEX)


def _example(name: str) -> tuple[type, str, dict]:
    text = (EXAMPLES / name).read_text(encoding='utf-8')  # universal newlines: CRLF checkouts parse the same
    return getattr(uc, INDEX[name]['model']), text, strict_json(text)


def test_index_lists_every_example_file():
    on_disk = {p.name for p in EXAMPLES.iterdir()} - {'index.json'}
    assert on_disk == set(NAMES)
    assert {INDEX[n]['valid'] for n in NAMES} == {True, False}


@pytest.mark.parametrize('name', [n for n in NAMES if INDEX[n]['valid']],
                         ids=[f'v{i}' for i, n in enumerate(n for n in NAMES if INDEX[n]['valid'])])
def test_valid_examples_round_trip(name):
    model, text, doc = _example(name)
    record = model.model_validate_json(text)
    assert record.model_dump(mode='json') == doc
    assert model.model_validate_json(json.dumps(record.model_dump(mode='json'))) == record


@pytest.mark.parametrize('name', [n for n in NAMES if not INDEX[n]['valid']],
                         ids=[f'i{i}' for i, n in enumerate(n for n in NAMES if not INDEX[n]['valid'])])
def test_invalid_examples_rejected_for_their_reason(name):
    model, text, _doc = _example(name)
    with pytest.raises(ValidationError) as info:
        model.model_validate_json(text)
    assert INDEX[name]['expect'] in str(info.value)


def _tree(folder: Path) -> dict[str, str]:
    return {p.relative_to(folder).as_posix(): p.read_text(encoding='utf-8') for p in sorted(folder.rglob('*'))
            if p.is_file()}


def test_generate_schemas_reproduces_committed_files(tmp_path, monkeypatch):
    """Regenerate-and-compare (CI drift gate, T-24). The pre-SPEC-31 schemas must regenerate unchanged too:
    S0a is additive only (secondary/2, engine-run/1, enrichment/1, model schema_version 1 untouched)."""
    monkeypatch.chdir(tmp_path)
    runpy.run_path(str(ROOT / 'tools' / 'generate_schemas.py'), run_name='__main__')
    produced = tmp_path / 'docs' / 'schemas'
    assert _tree(produced / 'unified') == _tree(SCHEMAS / 'unified')
    for name in ('enrichment', 'secondary', 'profile'):
        assert _tree(produced / name) == _tree(SCHEMAS / name)
    for path in produced.glob('*.json'):
        assert path.read_text(encoding='utf-8') == (SCHEMAS / path.name).read_text(encoding='utf-8')


def _atom(**over):
    data = dict(source='ghidriff', step='SymbolsHash', tier='A', cardinality='1:1', cls='E-NAME', older_rva=16,
                newer_rva=32)
    data.update(over)
    return uc.Atom(**data)


def _row(**over):
    data = dict(row_id='a' * 64, older=(uc.SideRef(rva=16, kind='function'),),
                newer=(uc.SideRef(rva=32, kind='function'),), decision='matched', atoms=(_atom(),))
    data.update(over)
    return uc.UnifiedMatch(**data)


def test_records_are_strict_and_frozen():
    with pytest.raises(ValidationError):
        uc.UnifiedMatch.model_validate({**_row().model_dump(), 'older': [{'rva': 16, 'kind': 'function'}]})
    with pytest.raises(ValidationError):
        _atom(older_rva=True)
    with pytest.raises(ValidationError):
        _atom(older_rva=1.0)
    with pytest.raises(ValidationError):
        _atom(surprise=1)
    with pytest.raises(ValidationError):
        _atom(native=(('label', '\ud800'),))
    with pytest.raises(ValidationError):
        _row().__setattr__('decision', 'candidate')


@pytest.mark.parametrize('over, text', [
    (dict(decision='older-only'), 'older-only'),
    (dict(newer=(), decision='matched'), 'both sides'),
    (dict(decision='contested'), 'needs its contest'),
    (dict(contest=uc.Contest(strength='weak', against=(0,))), 'contest is shown'),
    (dict(support=(uc.Support(component='K1', tier='B', atom_index=0),)), 'same tier'),
    (dict(older=(uc.SideRef(rva=32, kind='function'), uc.SideRef(rva=16, kind='function'))), 'sorted'),
    (dict(decision='older-only', newer=(), materiality='material'), 'not-applicable'),
], ids=['r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7'])
def test_row_invariants(over, text):
    with pytest.raises(ValidationError) as info:
        _row(**over)
    assert text in str(info.value)


def test_contest_strength_follows_against_tiers():
    atoms = (_atom(), _atom(source='rz-diff', step='levenshtein-bytes', tier='W', cardinality='non-exclusive',
                            cls='E-BODY', newer_rva=48))
    row = _row(decision='contested', atoms=atoms, contest=uc.Contest(strength='weak', against=(1,)))
    assert row.contest.strength == 'weak'
    with pytest.raises(ValidationError):
        _row(decision='contested', atoms=atoms, contest=uc.Contest(strength='strong', against=(1,)))
    manual = (_atom(source='manual', step='manual-correction', tier='M', cls='E-MANUAL'), atoms[1])
    assert _row(atoms=manual, contest=uc.Contest(strength='weak', against=(1,))).decision == 'matched'


def _facts(**over):
    data = dict(row_id='a' * 64, verdict='unchanged', proof='UNCH/1', channels=tuple((c, 'equal') for c in uc.CHANNELS),
                eh='equal')
    data.update(over)
    return uc.ChangeFacts(**data)


def test_change_fact_proof_rules():
    assert _facts().proof == 'UNCH/1'
    differs_c0 = tuple((c, 'differs' if c == 'C0' else 'equal') for c in uc.CHANNELS)
    for over, text in ((dict(channels=differs_c0), 'needs C0 equal'), (dict(targets=(2, 1, 0)), 'mapped'),
                       (dict(eh='unavailable'), 'EH-EQ'), (dict(proof='COS-ADDR/1'), 'unchanged needs'),
                       (dict(channels=tuple(reversed(_facts().channels))), 'in order'),
                       (dict(deltas=(uc.Delta(cls='callee', channel='C2', older_rva=1, newer_rva=2),)),
                        'no semantic delta')):
        with pytest.raises(ValidationError) as info:
            _facts(**over)
        assert text in str(info.value)
    frame = (uc.Delta(cls='frame', channel='C2', older_rva=1, newer_rva=2),)
    assert _facts(verdict='review', proof=None, deltas=frame).verdict == 'review'
    with pytest.raises(ValidationError) as info:  # frame/register/address deltas never make material
        _facts(verdict='material', proof=None, second_channel='C6', deltas=frame,
               channels=tuple((c, 'differs') for c in uc.CHANNELS))
    assert 'semantic delta' in str(info.value)


def test_unified_run_status_rules_and_sanitised_stderr():
    base = dict(run_id='b' * 64, result_id=None, status='cancelled', error_code='PT-UNIFIED-CANCEL',
                started_utc='2026-10-14T12:00:00+00:00', duration_ms=5)
    assert uc.UnifiedRun(**base).status == 'cancelled'
    for over in (dict(error_code='PT-UNIFIED-STORE'), dict(result_id='c' * 64),
                 dict(stderr_tail='x' * (DEFAULT_LIMITS.l31_stderr_tail_bytes + 1)),
                 dict(provenance={f'k{i}': 'v' for i in range(17)}), dict(started_utc='yesterday')):
        with pytest.raises(ValidationError):
            uc.UnifiedRun(**{**base, **over})
    assert uc.UnifiedRun(**{**base, 'stderr_tail': 'line one\n\tline two'}).stderr_tail.count('\n') == 1


def test_extract_request_paths_are_platform_independent():
    req = json.loads((EXAMPLES / 'valid-ExtractRequest-gzf.json').read_text(encoding='utf-8'))
    windows = {**req, 'artifact_path': 'C:\\Work\\pt-ir-1\\older.bin', 'gzf_path': 'D:/x/older.gzf'}
    assert uc.ExtractRequest.model_validate_json(json.dumps(windows)).side == 'older'
    for over in ({'work_dir': '/work/.hidden/ghidra'}, {'out_dir': '/' + 'a' * 240}, {'mode': 'analyze'},
                 {'decompile_rvas': [5]}, {'max_heap_mb': 256}):
        with pytest.raises(ValidationError):
            uc.ExtractRequest.model_validate_json(json.dumps({**req, **over}))


def test_counts_are_balanced_and_counted_from_rows():
    counts = uc.Counts.of([_row(), _row(decision='older-only', newer=(), materiality='not-applicable')])
    assert counts.total() == 2 and counts.decisions.older_only == 1 and counts.materiality.not_applicable == 1
    bad = counts.model_dump()
    bad['materiality']['unknown'] += 1
    with pytest.raises(ValidationError):
        uc.Counts.model_validate_json(json.dumps(bad))


def test_unified_error_codes_and_exit_codes():
    err = UnifiedError('PT-UNIFIED-CANCEL', 'Cancelled', reason='cancelled')
    assert (err.exit_code, err.recoverable, err.reason) == (5, True, 'cancelled')
    assert UnifiedError('PT-UNIFIED-INPUT', 'x').exit_code == 2
    assert not UnifiedError('PT-UNIFIED-INTERNAL', 'x').recoverable
    with pytest.raises(ValueError):
        UnifiedError('PT-UNIFIED-NOPE', 'x')
    with pytest.raises(ValueError):
        UnifiedError('PT-UNIFIED-IR', 'x', reason='Bad Reason')
    assert uc.UnifiedError is UnifiedError


def test_limits_defaults_follow_the_spec_table():
    lim = DEFAULT_LIMITS
    assert (lim.l01_functions_per_side, lim.l28_deltas_per_pair, lim.l31_pointer_body_bytes, lim.l32_results_kept,
            lim.l39_atoms_per_row, lim.l42_worker_mem_max_bytes) == (250_000, 64, 128 * 1024, 3, 64, 4 * 1024 ** 3)
    assert lim.l38_rows_per_result == 500_000
    assert lim.worker_memory_cap(2 * 1024 ** 3) == 1024 ** 3 and lim.worker_memory_cap(None) == 4 * 1024 ** 3
    assert lim.jvm_heap_mib(64 * 1024 **3) == 16_384 and lim.jvm_heap_mib(None) == 512
    assert lim.checked_timeout(60) == 60
    with pytest.raises(UnifiedError):
        lim.checked_timeout(59)
    for bad in (dict(l18_neighbour_cap=0), dict(l18_neighbour_cap=True), dict(l21_size_ratio_min_milli=3000)):
        with pytest.raises(ValueError):
            UnifiedLimits(**bad)


@pytest.mark.parametrize('over', [dict(l24_assign_bucket_cap=100_000), dict(l20_cosine_min_milli=5000),
                                  dict(l24_score_floor_milli=1001), dict(l03_heap_max_mib=100),
                                  dict(l21_size_ratio_min_milli=1500), dict(l21_size_ratio_max_milli=900)],
                         ids=['bucket', 'cosine', 'floor', 'heap', 'ratio-min', 'ratio-max'])
def test_limits_reject_impossible_combinations(over):
    """F-21: a cosine above 1.0 can never be met, a heap below the 512 MiB floor can never start, ..."""
    with pytest.raises(ValueError):
        UnifiedLimits(**over)


def test_checked_timeout_rejects_an_unknown_kind():
    assert DEFAULT_LIMITS.checked_timeout(60, kind='worker') == 60
    with pytest.raises(ValueError):
        DEFAULT_LIMITS.checked_timeout(60, kind='extrcat')


def test_budget_tick_rejects_negative_and_non_integer_units():
    """F-21: tick(-100000) used to delay every deadline check by that many units."""
    budget = Budget(None, check_every=1)
    for bad in (-1, 1.5, True, '1'):
        with pytest.raises(ValueError):
            budget.tick(bad)
    budget.tick(0)
    budget.tick(3)
    assert budget.used == 3


def test_budget_exhausted_is_only_cancel_or_timeout():
    """F-25: BudgetExhausted used to accept any code."""
    assert BudgetExhausted('PT-UNIFIED-TIMEOUT', 'x').exit_code == 3
    with pytest.raises(ValueError):
        BudgetExhausted('PT-UNIFIED-STORE', 'x')


def test_budget_checks_every_n_units_with_injected_clock():
    now = [0.0]
    budget = Budget.after(10, check_every=4, clock=lambda: now[0])
    now[0] = 20.0
    budget.tick(3)  # below the check interval: no clock read yet
    with pytest.raises(BudgetExhausted) as info:
        budget.tick(1)
    assert info.value.code == 'PT-UNIFIED-TIMEOUT'
    cancel = threading.Event()
    budget = Budget(None, cancel, check_every=1)
    budget.tick()
    cancel.set()
    assert budget.expired()
    with pytest.raises(BudgetExhausted) as info:
        budget.check()
    assert info.value.code == 'PT-UNIFIED-CANCEL' and isinstance(info.value, UnifiedError)


# --- S0a-FIX (audit C): text, time, ids, paths, facts, runs, pointer versions -------------------------------------

HOSTILE = ['a\n\x1b[31m', 'a\u202eb', 'a\r\nb', 'a\u200fb\u061cc\ufeff', 'a\x00b', '\u2028x\u2029', 'x\u00ady', 'a\x7fb',
           'a\x85b', 'a\u2066b\u2069', 'a\u200bb\u2060c', 'a\U000e0041b']
UNSAFE = uc._UNSAFE_TEXT


def _example_doc(name: str) -> dict:
    return json.loads((EXAMPLES / name).read_text(encoding='utf-8'))


@pytest.mark.parametrize('text', HOSTILE, ids=[f'h{i}' for i in range(len(HOSTILE))])
def test_display_text_is_sanitised_on_construction(text):
    """F-08: names, instruction text and notes come from untrusted binaries; they reach the GUI, logs and exports.
    They are neutralised (length-preserving U+FFFD), never rejected, so a hostile symbol cannot block a result."""
    built = [_atom(step=text).step, _atom(ref=text).ref, _atom(native=((text[:32] or 'x', text),)).native[0][1],
             uc.SideRef(rva=1, name=text, kind='function').name, uc.Delta(
                 cls='constant', channel='C2', older_rva=1, newer_rva=2, old=text, new=text).old,
             _row(hints=(text,)).hints[0]]
    for value in built:
        assert len(value) == len(text) and not UNSAFE.search(value)
        assert any(ch == '\ufffd' for ch in value) and value[0] in ('a', 'x', '\ufffd')
    assert uc.SideRef(rva=1, name=built[3], kind='function').name == built[3]  # idempotent


def test_ordinary_unicode_text_is_untouched():
    for name in ('plain_ascii', 'Ünïcode-名前', 'emoji 🙂', '?AVfoo@@ (std::vector<int>) [x]'):
        assert uc.SideRef(rva=1, name=name, kind='function').name == name


@pytest.mark.parametrize('text', ['a\nb', 'a\x00b', 'a\u202eb', 'a\u200bb'], ids=['lf', 'nul', 'bidi', 'zw'])
def test_identifier_and_protocol_text_is_rejected_not_rewritten(text):
    ref = dict(source='ghidriff', entry_id='run-1', file_sha256=None, version='1.0')
    for over in (dict(entry_id=text), dict(version=text)):
        with pytest.raises(ValidationError):
            uc.SourceRef(**{**ref, **over})
    with pytest.raises(ValidationError):
        _row(ghidriff_match_id=text)
    doc = _example_doc('valid-IrExtractHeader.json')
    with pytest.raises(ValidationError):
        uc.IrExtractHeader.model_validate_json(json.dumps({**doc, 'compiler': text}))


def test_identity_text_must_be_nfc_normalised():
    """F-23: 'e' + combining acute and the precomposed letter hash alike but were two distinct SourceRefs."""
    ref = dict(source='ghidriff', file_sha256=None, version='1.0')
    assert uc.SourceRef(entry_id='\u00e9', **ref).entry_id == '\u00e9'
    with pytest.raises(ValidationError):
        uc.SourceRef(entry_id='e\u0301', **ref)


def test_stderr_tail_folds_crlf_and_neutralises_hostile_characters():
    """F-09: a Windows child writes CRLF; the record that reports the failure must be buildable."""
    base = dict(run_id='b' * 64, result_id=None, status='failed', error_code='PT-UNIFIED-EXTRACT',
                started_utc='2026-10-14T12:00:00+00:00', duration_ms=5)
    assert uc.UnifiedRun(**base, stderr_tail='one\r\ntwo\rthree\tx\n').stderr_tail == 'one\ntwo\nthree\tx\n'
    for hostile in ('bad\x1b[31m', 'a\u200fb\u061cc\ufeff', 'x\u2066y', 'a\u2028b'):
        tail = uc.UnifiedRun(**base, stderr_tail=hostile).stderr_tail
        assert not uc._STDERR_UNSAFE.search(tail) and len(tail) == len(hostile)


@pytest.mark.parametrize('stamp', ['2026-13-45T99:99:99Z', '２０２６-10-14T00:00:00Z', '2026-02-30T00:00:00Z',
                                   '2026-10-14T12:00:00+01:00', '2026-10-14 12:00:00Z', '2026-10-14T12:00:00'],
                         ids=['range', 'wide', 'feb30', 'offset', 'space', 'naive'])
def test_utc_is_a_calendar_timestamp(stamp):
    """F-11: the regex alone accepted month 13, hour 99 and fullwidth digits."""
    with pytest.raises(ValidationError):
        uc.UnifiedRun(run_id='b' * 64, result_id=None, status='cancelled', error_code='PT-UNIFIED-CANCEL',
                      started_utc=stamp, duration_ms=1)


def test_utc_has_one_spelling_per_instant():
    base = dict(run_id='b' * 64, result_id=None, status='cancelled', error_code='PT-UNIFIED-CANCEL', duration_ms=1)
    z = uc.UnifiedRun(**base, started_utc='2026-10-14T12:00:00Z')
    plus = uc.UnifiedRun(**base, started_utc='2026-10-14T12:00:00+00:00')
    assert z == plus and z.started_utc == '2026-10-14T12:00:00+00:00'
    assert uc.UnifiedRun(**base, started_utc='2026-10-14T12:00:00.5Z').started_utc == '2026-10-14T12:00:00.500000+00:00'
    assert uc.UnifiedRun.model_validate_json(z.model_dump_json()) == z


@pytest.mark.parametrize('run_id', ['CON', 'nul', 'aux.txt', 'abc.', 'COM1', 'lpt9.log', 'Prn'],
                         ids=['con', 'nul', 'aux', 'dot', 'com1', 'lpt9', 'prn'])
def test_run_ids_refuse_windows_device_names_and_trailing_dots(run_id):
    """F-06: these names alias devices or other directories on Windows (`abc.` is `abc`)."""
    doc = _example_doc('valid-UnifiedResultManifest.json')
    with pytest.raises(ValidationError):
        uc.UnifiedResultManifest.model_validate_json(json.dumps({**doc, 'ghidriff_run_id': run_id}))
    pointer = _example_doc('valid-UnifiedResultPointer.json')
    pointer['relative_dir'] = f'runs/{run_id}/unified/results/{pointer["result_id"][:16]}'
    with pytest.raises(ValidationError):
        uc.UnifiedResultPointer.model_validate_json(json.dumps(pointer))
    for fine in ('run-1', 'conx', 'a.b', 'console'):
        assert uc.UnifiedResultManifest.model_validate_json(json.dumps({**doc, 'ghidriff_run_id': fine}))


def test_pointer_v2_adds_the_pair_and_v1_stays_readable():
    """F-01/F-18: additive means a new /N with a version-gated reader."""
    v1 = _example_doc('valid-UnifiedResultPointer.json')
    v2 = _example_doc('valid-UnifiedResultPointerV2.json')
    old, new = uc.parse_pointer(v1), uc.parse_pointer(v2)
    assert type(old) is uc.UnifiedResultPointer and type(new) is uc.UnifiedResultPointerV2
    assert isinstance(new, uc.UnifiedResultPointer) and (new.older_sha256, new.newer_sha256) == (
        v2['older_sha256'], v2['newer_sha256'])
    for bad in ({**v2, 'older_sha256': None}, {**v1, 'older_sha256': 'a' * 64},
                {key: value for key, value in v2.items() if key != 'newer_sha256'}):
        with pytest.raises(ValidationError):
            uc.parse_pointer(bad)
    with pytest.raises(UnifiedError) as info:
        uc.parse_pointer({**v2, 'contract': 'unified-result-ptr/3'})
    assert (info.value.code, info.value.reason) == ('PT-UNIFIED-STALE', 'newer-contract')
    for odd in ('unified-result-ptr/0', 'unified-result-ptr/', 'unified-result-ptr/x', 'other/9', None):
        with pytest.raises(ValidationError):
            uc.parse_pointer({**v2, 'contract': odd})
    with pytest.raises(ValidationError):
        uc.parse_pointer([])


def test_newer_contract_is_numeric_and_per_family():
    assert uc.newer_contract('unified-result/2', 'unified-result/1')
    assert uc.newer_contract('unified-result/10', 'unified-result/9')
    for found in ('unified-result/1', 'unified-result/0', 'unified-result/', 'unified-result/abc', 'unified-run/2',
                  None, 7):
        assert not uc.newer_contract(found, 'unified-result/1')


def test_unchanged_and_cosmetic_facts_carry_no_structural_delta():
    """F-16: UNCH/1 means the bytes are equal; only COS-LAYOUT/1 may carry a block delta."""
    for cls in ('cfg', 'unknown', 'block-added', 'block-removed'):
        delta = (uc.Delta(cls=cls, channel='C2', older_rva=None, newer_rva=5),)
        with pytest.raises(ValidationError) as info:
            _facts(deltas=delta)
        assert 'structural delta' in str(info.value)
    layout = dict(verdict='cosmetic', proof='COS-LAYOUT/1')
    block = (uc.Delta(cls='block-added', channel='C2', older_rva=None, newer_rva=5),)
    assert _facts(**layout, deltas=block).proof == 'COS-LAYOUT/1'
    for cls in ('cfg', 'unknown'):
        with pytest.raises(ValidationError):
            _facts(**layout, deltas=(uc.Delta(cls=cls, channel='C2', older_rva=5, newer_rva=6),))
    with pytest.raises(ValidationError):
        _facts(verdict='cosmetic', proof='COS-ADDR/1', deltas=block)


def test_delta_needs_an_endpoint_and_the_omitted_count_is_bounded():
    with pytest.raises(ValidationError):
        uc.Delta(cls='frame', channel='C2', older_rva=None, newer_rva=None)
    assert _facts(deltas_omitted=5).deltas_omitted == 5
    with pytest.raises(ValidationError):
        _facts(deltas_omitted=10 ** 12)
    with pytest.raises(ValidationError):
        _facts(deltas_omitted=-1)


def _run(**over):
    base = dict(run_id='b' * 64, result_id=None, status='failed', error_code='PT-UNIFIED-EXTRACT',
                started_utc='2026-10-14T12:00:00+00:00', duration_ms=5)
    return uc.UnifiedRun(**{**base, **over})


@pytest.mark.parametrize('code', ['PT-UNIFIED-CANCEL', 'PT-UNIFIED-TIMEOUT', 'PT-UNIFIED-UNSUPPORTED'],
                         ids=['cancel', 'timeout', 'unsupported'])
def test_a_failed_run_never_carries_another_status_code(code):
    """F-13: those codes have statuses of their own."""
    with pytest.raises(ValidationError):
        _run(status='failed', error_code=code)
    assert _run(status='failed', error_code='PT-UNIFIED-STORE').status == 'failed'


def test_a_partial_run_is_neither_cancelled_nor_unsupported_and_names_its_cause():
    partial = dict(status='partial', result_id='c' * 64)
    for code in ('PT-UNIFIED-CANCEL', 'PT-UNIFIED-UNSUPPORTED'):
        with pytest.raises(ValidationError):
            _run(**partial, error_code=code)
    with pytest.raises(ValidationError):
        _run(**partial, error_code=None)
    ok = (uc.StageRecord(stage='match', status='ok', duration_ms=1),)
    with pytest.raises(ValidationError):
        _run(**partial, error_code=None, stages=ok)
    assert _run(**partial, error_code='PT-UNIFIED-TIMEOUT').status == 'partial'  # a spent budget keeps its passes
    cause = (*ok, uc.StageRecord(stage='source', status='failed', duration_ms=1, reason='source-failed'))
    assert _run(**partial, error_code=None, stages=cause).status == 'partial'


def test_provenance_and_request_maps_are_clean_and_immutable():
    """F-12: Python `$` accepted 'a\\n', values were unsanitised and the frozen model kept a mutable dict."""
    run = _run(provenance={'worker': 'in-process', 'note': 'x\x00y\n'})
    assert run.provenance['note'] == 'x\ufffdy\ufffd' and hash(run) == hash(copy.deepcopy(run))
    with pytest.raises(TypeError):
        run.provenance['extra'] = 'v'
    with pytest.raises(TypeError):
        run.provenance.update(extra='v')
    assert copy.deepcopy(run) == run and uc.UnifiedRun.model_validate_json(run.model_dump_json()) == run
    assert run.model_dump(mode='json')['provenance'] == {'worker': 'in-process', 'note': 'x\ufffdy\ufffd'}
    with pytest.raises(ValidationError):
        _run(provenance={'a\n': 'v'})
    with pytest.raises(ValidationError):
        _run(provenance={'k': 'v' * 257})
    request = uc.ExtractRequest.model_validate_json((EXAMPLES / 'valid-ExtractRequest-gzf.json').read_text('utf-8'))
    with pytest.raises(TypeError):
        request.limits['l01_functions_per_side'] = 1
    with pytest.raises(TypeError):
        request.analysis_options['k'] = 'v'


def _request(**over) -> str:
    doc = json.loads((EXAMPLES / 'valid-ExtractRequest-gzf.json').read_text(encoding='utf-8'))
    return json.dumps({**doc, **over})


@pytest.mark.parametrize('path', ['/a/b\n', '/a/b\x00c', '/a/b\u202ec', '//a', '//server/share', '/', 'C:\\', 'C:/',
                                  '/a/b.', '/a/b ', '/work/CON', 'C:\\work\\nul.txt', '/work/Aux.log',
                                  '\\\\server\\share\\x'],
                         ids=['lf', 'nul', 'bidi', 'dslash', 'unc', 'root', 'cdrive', 'cslash', 'dot', 'space', 'con',
                              'nultxt', 'aux', 'bsunc'])
def test_extract_request_refuses_hostile_paths(path):
    """F-10: NUL crashes at spawn, a newline breaks the line-oriented log files, device names alias on Windows."""
    for field in ('artifact_path', 'out_dir', 'work_dir'):
        with pytest.raises(ValidationError):
            uc.ExtractRequest.model_validate_json(_request(**{field: path}))


def test_extract_request_accepts_the_ordinary_paths():
    for path in ('/work/pt-ir-1/out', 'C:\\Work\\pt-ir-1\\out', 'D:/x/y', '/work/consoles/aux1/out'):
        assert uc.ExtractRequest.model_validate_json(_request(out_dir=path)).out_dir == path


@pytest.mark.parametrize('over', [dict(limits={'l99_whatever': 10}), dict(limits={'l01_functions_per_side': 10 ** 30}),
                                  dict(limits={'l01_functions_per_side': 0}),
                                  dict(limits={'l01_functions_per_side': 2 ** 63}),
                                  dict(analysis_options={'a': 'x\n'}, mode='analyze', gzf_path=None, gzf_sha256=None),
                                  dict(mode='decompile', gzf_path=None, gzf_sha256=None, decompile_rvas=[4096]),
                                  dict(mode='decompile', decompile_rvas=[])],
                         ids=['unknown', 'huge', 'zero', 'long', 'option', 'nogzf', 'norva'])
def test_extract_request_bounds_limits_options_and_decompile_inputs(over):
    with pytest.raises(ValidationError):
        uc.ExtractRequest.model_validate_json(_request(**over))
    ok = uc.ExtractRequest.model_validate_json(_request(mode='decompile', decompile_rvas=[4096]))
    assert ok.mode == 'decompile' and ok.limits == {'l01_functions_per_side': 250000}


def test_ghidra_producers_record_their_script_and_options():
    doc = _example_doc('valid-ProgramIrManifest.json')
    for field in ('script_sha256', 'analysis_options_digest'):
        bad = json.loads(json.dumps(doc))
        bad['producer'][field] = None
        with pytest.raises(ValidationError):
            uc.ProgramIrManifest.model_validate_json(json.dumps(bad))


@st.composite
def match_rows(draw):
    decision = draw(st.sampled_from(['matched', 'older-only', 'newer-only']))
    side = st.lists(st.integers(0, 2 ** 32 - 1), unique=True, min_size=1, max_size=3).map(sorted)
    older = draw(side) if decision != 'newer-only' else []
    newer = draw(side) if decision != 'older-only' else []
    name = draw(st.one_of(st.none(), st.text(max_size=20)))  # any text: controls, bidi and format characters included

    def refs(rvas):
        return tuple(uc.SideRef(rva=rva, name=name, kind='function') for rva in rvas)
    materiality = draw(st.sampled_from(['unchanged', 'material', 'review', 'unknown'])) \
        if decision == 'matched' else 'not-applicable'
    return uc.UnifiedMatch(row_id=keys.row_id('a' * 64, 'b' * 64, older, newer), older=refs(older), newer=refs(newer),
                           decision=decision, atoms=(), materiality=materiality)


@settings(max_examples=60, deadline=None)
@given(rows=st.lists(match_rows(), max_size=5))
def test_rows_survive_a_json_round_trip_with_clean_names_and_balanced_counts(rows):
    """F-20: sanitising is idempotent and length-preserving, so a stored row reads back as itself."""
    for row in rows:
        assert uc.UnifiedMatch.model_validate_json(row.model_dump_json()) == row
        assert not any(UNSAFE.search(ref.name or '') for ref in (*row.older, *row.newer))
    counts = uc.Counts.of(rows)
    assert counts.total() == len(rows) == sum(counts.materiality.model_dump().values())


@settings(max_examples=60, deadline=None)
@given(moment=st.datetimes(min_value=datetime(1970, 1, 1), max_value=datetime(9998, 12, 31)))
def test_canonical_utc_is_idempotent_and_independent_of_the_spelling(moment):
    text = moment.isoformat(timespec='microseconds')
    z, plus = uc.canonical_utc(text + 'Z'), uc.canonical_utc(text + '+00:00')
    assert z == plus and z.endswith('+00:00') and uc.canonical_utc(z) == z


def test_schemas_describe_the_cross_field_rules():
    """F-24: non-Python consumers (the Ghidra-side script, GUI code) read the schema, not the validators."""
    for name in ('UnifiedMatch', 'ChangeFacts', 'UnifiedRun', 'ExtractRequest', 'UnifiedResultPointerV2'):
        schema = json.loads((SCHEMAS / 'unified' / f'{name}.json').read_text(encoding='utf-8'))
        assert len(schema['description']) > 80, name


ALLOWED = {'__init__': set(), 'limits': set(), 'contracts': {'pydantic', 'patchtrace.unified.limits'},
           'keys': {'patchtrace.enrichment.identity', 'patchtrace.unified.contracts', 'patchtrace.unified.limits'},
           'store': {'pydantic', 'patchtrace.enrichment.contracts', 'patchtrace.enrichment.storage',
                     'patchtrace.ingestion', 'patchtrace.persistence', 'patchtrace.unified',
                     'patchtrace.unified.contracts', 'patchtrace.unified.limits'}}
STDLIB = {'__future__', 'collections', 'collections.abc', 'dataclasses', 'datetime', 'gzip', 'hashlib', 'json', 'os',
          're', 'secrets', 'shutil', 'sqlite3', 'stat', 'time', 'typing', 'pathlib', 'unicodedata', 'zlib'}


@pytest.mark.parametrize('module', sorted(ALLOWED))
def test_s0a_modules_respect_import_rules(module):
    path = ROOT / 'src' / 'patchtrace' / 'unified' / f'{module}.py'
    imported = set()
    for node in ast.walk(ast.parse(path.read_text(encoding='utf-8'))):
        if isinstance(node, ast.Import):
            imported |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ''
            if node.level:
                parent = 'patchtrace' if node.level == 2 else 'patchtrace.unified'
                base = f'{parent}.{base}' if base else parent
            imported.add(base)
    assert imported - STDLIB <= ALLOWED[module]


def test_unified_package_imports_no_qt_network_or_process_modules():
    code = ('import sys\nclass Block:\n    def find_spec(self, name, path=None, target=None):\n'
            '        if name.split(".")[0] == "PySide6": raise ImportError("blocked")\n'
            'sys.meta_path.insert(0, Block())\n'
            'import patchtrace.unified.store, patchtrace.unified.keys\n'
            # socket is imported transitively by persistence.ProjectLock (hostname only); the AST test above
            # proves no unified module imports it directly.
            'bad = [m for m in ("PySide6", "subprocess", "ssl", "urllib.request", "http.client")\n'
            '       if m in sys.modules]\nprint(bad)\nraise SystemExit(1 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
