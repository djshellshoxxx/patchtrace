"""SPEC-31 S0a contracts: committed schemas and valid/invalid examples, strictness, invariants, limits, budget.
Synthetic data only; nothing here is live evidence."""
from __future__ import annotations

import ast
import json
import os
import runpy
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from pydantic import ValidationError

from patchtrace.persistence import strict_json
from patchtrace.unified import contracts as uc
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
    for over in (dict(error_code='PT-UNIFIED-STORE'), dict(result_id='c' * 64), dict(stderr_tail='bad\x1b[31m'),
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


ALLOWED = {'__init__': set(), 'limits': set(), 'contracts': {'pydantic', 'patchtrace.unified.limits'},
           'keys': {'patchtrace.enrichment.identity', 'patchtrace.unified.contracts', 'patchtrace.unified.limits'},
           'store': {'pydantic', 'patchtrace.enrichment.contracts', 'patchtrace.enrichment.storage',
                     'patchtrace.ingestion', 'patchtrace.persistence', 'patchtrace.unified',
                     'patchtrace.unified.contracts', 'patchtrace.unified.limits'}}
STDLIB = {'__future__', 'collections', 'collections.abc', 'dataclasses', 'datetime', 'gzip', 'hashlib', 'json', 'os',
          're', 'secrets', 'shutil', 'sqlite3', 'stat', 'time', 'typing', 'pathlib'}


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
