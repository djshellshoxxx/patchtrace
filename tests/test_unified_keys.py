"""SPEC-31 S0a identities and cache keys (02 s5): input coverage, order independence, determinism across
processes and hash seeds, and the R-09 rule that ladder limits never change the IR key. Synthetic inputs only."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from patchtrace.enrichment.identity import canonical_json
from patchtrace.unified import keys
from patchtrace.unified.contracts import IrKeyInputs, ResultKeyInputs, SourceRef
from patchtrace.unified.limits import DEFAULT_LIMITS, UnifiedLimits

ROOT = Path(__file__).resolve().parents[1]
H = {k: hashlib.sha256(k.encode()).hexdigest() for k in ('o', 'n', 'raw', 'man', 'cfg', 'ir1', 'ir2', 's1', 'x')}
SOURCES = (SourceRef(source='ghidriff', entry_id='r1', file_sha256=H['raw'], version='1.0.0'),
           SourceRef(source='rz-diff', entry_id='set-1', file_sha256=H['s1'], version='0.9.1'))


def result_inputs(**over) -> ResultKeyInputs:
    data = dict(older_sha256=H['o'], newer_sha256=H['n'], ghidriff_raw_sha256=H['raw'], ir_older_digest=H['ir1'],
                ir_newer_digest=H['ir2'], sources=SOURCES, manual_digest=H['man'], config_digest=H['cfg'])
    data.update(over)
    return ResultKeyInputs(**data)


def ir_inputs(**over) -> IrKeyInputs:
    data = dict(artifact_sha256=H['o'], producer_kind='ghidra', mode='gzf', symbols='none', ghidra='12.0.4',
                pyghidra='3.0.2', python='3.12.10', script_sha256=H['x'], analysis_options_digest=H['cfg'],
                ingest_limits_digest=keys.ingest_limits_digest())
    data.update(over)
    return IrKeyInputs(**data)


def test_row_id_follows_the_documented_domain_formula():
    expected = hashlib.sha256(b'patchtrace\x00unified-row\x001\x00' + canonical_json(
        {'older_sha256': H['o'], 'newer_sha256': H['n'], 'older_rvas': [16, 32], 'newer_rvas': [48]})).hexdigest()
    assert keys.row_id(H['o'], H['n'], [32, 16], [48]) == expected


@pytest.mark.parametrize('bad', [([1, 1], [2]), ([-1], [2]), ([2**32], [1]), ([True], [1]), ([], [])],
                         ids=['dup', 'neg', 'big', 'bool', 'empty'])
def test_row_id_rejects_bad_rvas(bad):
    with pytest.raises(ValueError):
        keys.row_id(H['o'], H['n'], *bad)


CHANGES = {'older_sha256': H['x'], 'newer_sha256': H['x'], 'ghidriff_raw_sha256': H['x'], 'ir_older_digest': None,
           'ir_newer_digest': H['x'], 'sources': SOURCES[:1], 'manual_digest': H['x'], 'config_digest': H['x']}


@pytest.mark.parametrize('field', sorted(CHANGES), ids=[f'f{i}' for i in range(len(CHANGES))])
def test_result_key_changes_with_every_input(field):
    base = result_inputs()
    changed = result_inputs(**{field: CHANGES[field]})
    assert keys.result_key(changed) != keys.result_key(base)
    assert keys.changed_inputs(base, changed) == (field,)


def test_result_key_orientation_and_source_order():
    base = result_inputs()
    assert keys.result_key(result_inputs(older_sha256=H['n'], newer_sha256=H['o'])) != keys.result_key(base)
    assert keys.result_key(result_inputs(sources=tuple(reversed(SOURCES)))) == keys.result_key(base)
    assert keys.changed_inputs(base, result_inputs(sources=tuple(reversed(SOURCES)))) == ()
    assert keys.source_set_digest(SOURCES) == keys.source_set_digest(reversed(SOURCES))


def test_ir_key_ignores_ladder_limits_but_not_ingest_limits():
    base = keys.ir_key(ir_inputs())
    ladder = UnifiedLimits(l18_neighbour_cap=32)
    assert keys.ingest_limits_digest(ladder) == keys.ingest_limits_digest()
    assert keys.limits_digest(ladder) != keys.limits_digest()  # ...but the config digest does change (02 s5)
    assert keys.ir_key(ir_inputs(ingest_limits_digest=keys.ingest_limits_digest(
        UnifiedLimits(l06_fn_instructions=50_000)))) != base
    for over in (dict(symbols='primary'), dict(mode='analyze'), dict(ghidra='12.0.5')):
        assert keys.ir_key(ir_inputs(**over)) != base
    assert set(IrKeyInputs.model_fields) == {
        'artifact_sha256', 'producer_kind', 'mode', 'symbols', 'ghidra', 'pyghidra', 'python', 'script_sha256',
        'analysis_options_digest', 'ingest_version', 'norm_version', 'ingest_limits_digest'}  # no gzf/java (R-09)


def test_unknown_versions_are_not_cache_eligible():
    assert keys.ir_cache_eligible(ir_inputs())
    assert not keys.ir_cache_eligible(ir_inputs(pyghidra='unknown'))
    assert not keys.ir_cache_eligible(ir_inputs(ghidra=''))


def test_manual_digest_is_order_independent_and_normalised():
    a = keys.manual_digest([('matched', [0x1000], ['0X2000 ']), ('split', ['0x10', '0x20'], ['0x30'])])
    b = keys.manual_digest([('split', ['0x20', '0x10'], [48]), ('matched', ['0x1000'], [0x2000])])
    assert a == b and keys.manual_digest([]) != a
    with pytest.raises(ValueError):
        keys.manual_digest([('matched', [None], [1])])


def test_config_digest_covers_each_component():
    base = dict(pass_table_digest=H['x'], registry_digest=H['cfg'], channel_versions={'C0': 1},
                proof_versions={'UNCH/1': 1}, limits_digest=keys.limits_digest())
    digest = keys.config_digest(**base)
    for field, value in (('pass_table_digest', H['o']), ('registry_digest', H['o']), ('channel_versions', {'C0': 2}),
                         ('proof_versions', {}), ('limits_digest', keys.limits_digest(UnifiedLimits(
                             l32_results_kept=4)))):
        assert keys.config_digest(**{**base, field: value}) != digest


def test_keys_are_identical_across_processes_and_hash_seeds():
    code = ('import json, hashlib\nfrom patchtrace.unified import keys\n'
            'from patchtrace.unified.contracts import SourceRef, ResultKeyInputs\n'
            'h = lambda k: hashlib.sha256(k.encode()).hexdigest()\n'
            'src = tuple(SourceRef(source=s, entry_id=e, file_sha256=h(e), version="1") for s, e in '
            '[("rz-diff", "b"), ("ghidriff", "a"), ("bindiff", "c")])\n'
            'inp = ResultKeyInputs(older_sha256=h("o"), newer_sha256=h("n"), ghidriff_raw_sha256=h("r"), '
            'ir_older_digest=None, ir_newer_digest=None, sources=src, manual_digest=h("m"), config_digest=h("c"))\n'
            'print(json.dumps([keys.result_key(inp), keys.limits_digest(), keys.ingest_limits_digest(), '
            'keys.row_id(h("o"), h("n"), [3, 1, 2], [9]), keys.manual_digest([("x", {5, 1, 3}, [])])]))\n')
    outputs = set()
    for seed in ('1', '2'):
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED=seed)
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
        assert result.returncode == 0, result.stderr
        outputs.add(result.stdout.strip())
    assert len(outputs) == 1
    assert json.loads(outputs.pop())[1] == keys.limits_digest(DEFAULT_LIMITS)


def test_unified_run_id_is_an_event_identity():
    assert keys.unified_run_id(H['x'], '2026-10-14T12:00:00+00:00') != keys.unified_run_id(
        H['x'], '2026-10-14T12:00:01+00:00')
