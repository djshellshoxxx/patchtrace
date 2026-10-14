"""SPEC-31 S0a identities and cache keys (02 s5): input coverage, order independence, determinism across
processes and hash seeds, and the R-09 rule that ladder limits never change the IR key. Synthetic inputs only."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import string
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import assume, given, settings
from hypothesis import strategies as st

from patchtrace.enrichment.identity import canonical_json
from patchtrace.unified import keys
from patchtrace.unified.contracts import IrKeyInputs, ResultKeyInputs, SourceRef
from patchtrace.unified.limits import (
    CONTENT_LIMIT_FIELDS,
    DEFAULT_LIMITS,
    OPERATIONAL_LIMIT_FIELDS,
    UnifiedLimits,
)

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
                             l18_neighbour_cap=32)))):  # a content limit; l32_results_kept is operational (F-14)
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


# --- S0a-FIX (audit C): key formats are pinned, operational knobs never re-key, inputs are validated ---------------

GOLDEN = {
    'row_id': 'e632aa7ae442e6b8161fcb7d5b621bdfd08ee8d1ec44cf88ec5196cbfd5d95ee',
    'row_id_one_sided': '663d99e5dd7ebeac4fc67b7f6562e32b63a5475d1aef8a41b6b11edd9eef7291',
    'result_key': '68c7e0684d5504ed9a7c8b65fc7ce56973e0b6ec2172d699803c0208f0322b28',
    'source_set_digest': 'ba723712e6ce85d01394ae3e60b7ad54b756194943b68d1f54f6235c7f98c387',
    'manual_digest': '99b556e3a7daf5e547034449285f0fd099e0be71116a8019b194d1f2b1279511',
    'manual_digest_empty': 'a9adbdc4d34f2c90e9f3672b7e6bff65fe419699a061e2bb54c61b9bc41a7505',
    'ingest_limits_digest': '8ac9c2226c9b026ff33c24a5adf48a8ccd8ee48d4645c9e94ef793cfb7090fc4',
    'ir_key': '514c93bf4415f590bd9a613501e4eb8f721f49f5326cf4e6bcf1fea6f905830b',
    'config_digest': '71eb316ed629a03f815e4d500488c485257b60952176bf683f626853a0219e99',
    'unified_run_id': '806b53dbeeff3089f2b37994aed0c092116b1b4d95d0500ba644690398f0c089',
}


def test_golden_vectors_pin_every_key_format():
    """F-14: a refactor of canonical_json/domain_id, a pydantic default or a Python change that alters a key must
    fail here, not silently re-key (or worse, mis-share) every cached result."""
    got = {
        'row_id': keys.row_id(H['o'], H['n'], [32, 16], [48]),
        'row_id_one_sided': keys.row_id(H['o'], H['n'], [4096], []),
        'result_key': keys.result_key(result_inputs()),
        'source_set_digest': keys.source_set_digest(SOURCES),
        'manual_digest': keys.manual_digest([('matched', [0x1000], ['0X2000 ']),
                                             ('split', ['0x10', '0x20'], ['0x30'])]),
        'manual_digest_empty': keys.manual_digest([]),
        'ingest_limits_digest': keys.ingest_limits_digest(),
        'ir_key': keys.ir_key(ir_inputs()),
        'config_digest': keys.config_digest(pass_table_digest=H['x'], registry_digest=H['cfg'],
                                            channel_versions={'C0': 1}, proof_versions={'UNCH/1': 1},
                                            limits_digest=H['o']),
        'unified_run_id': keys.unified_run_id(H['x'], '2026-10-14T12:00:00+00:00'),
    }
    assert got == GOLDEN


def test_every_limit_is_classified_exactly_once():
    names = {f.name for f in dataclasses.fields(UnifiedLimits)}
    content, operational = set(CONTENT_LIMIT_FIELDS), set(OPERATIONAL_LIMIT_FIELDS)
    assert content | operational == names and not content & operational
    assert set(DEFAULT_LIMITS.content_dict()) == content


@pytest.mark.parametrize('over', [dict(l37_progress_poll_ms=100), dict(l32_results_kept=5),
                                  dict(l35_first_paint_ms=300), dict(l04_analyze_timeout_s=3600),
                                  dict(l33_displayed_rows=10)], ids=['poll', 'kept', 'paint', 'timeout', 'rows'])
def test_operational_limits_never_rekey_results(over):
    """F-14: a UI, retention or timeout knob cannot change a result, so it must not invalidate the cache."""
    assert keys.limits_digest(UnifiedLimits(**over)) == keys.limits_digest()


@pytest.mark.parametrize('over', [dict(l18_neighbour_cap=32), dict(l20_cosine_min_milli=900),
                                  dict(l28_deltas_per_pair=32), dict(l06_fn_instructions=50_000)],
                         ids=['cap', 'cosine', 'deltas', 'fn'])
def test_content_limits_rekey_results(over):
    assert keys.limits_digest(UnifiedLimits(**over)) != keys.limits_digest()


@pytest.mark.parametrize('bad', [dict(pass_table_digest='x'), dict(registry_digest=''), dict(limits_digest=None),
                                 dict(channel_versions={'C0': True}), dict(channel_versions={'C0': 1.0}),
                                 dict(proof_versions={1: 1}), dict(engine_version='')],
                         ids=['short', 'empty', 'none', 'bool', 'float', 'key', 'engine'])
def test_config_digest_rejects_malformed_components(bad):
    base = dict(pass_table_digest=H['x'], registry_digest=H['cfg'], channel_versions={'C0': 1},
                proof_versions={'UNCH/1': 1}, limits_digest=keys.limits_digest())
    with pytest.raises(ValueError):
        keys.config_digest(**{**base, **bad})


def test_row_id_and_run_id_require_sha256_text():
    with pytest.raises(ValueError):
        keys.row_id('not-a-hash', H['n'], [1], [2])
    with pytest.raises(ValueError):
        keys.unified_run_id('short', '2026-10-14T12:00:00+00:00')


def test_manual_digest_folds_equivalent_spellings():
    """F-22: 0x010, 0X10 and 16 are one address; a duplicate address and 1 versus '1' are not two corrections."""
    reference = keys.manual_digest([('matched', [16], [32])])
    for variant in ([('matched', ['0x010'], ['0X20'])], [('matched', [16, 16], ['0x20 ', 32])],
                    [('matched', ['0x10'], ['0x0020'])]):
        assert keys.manual_digest(variant) == reference
    assert keys.manual_digest([('matched', ['16'], [32])]) != reference  # decimal text stays text (ambiguous)
    with pytest.raises(ValueError):
        keys.manual_digest([(1, [1], [2])])


@pytest.mark.parametrize('stamp', ['2026-10-14T12:00:00Z', '2026-10-14T12:00:00.000000+00:00',
                                   '2026-10-14T12:00:00+00:00'], ids=['z', 'zero-us', 'plain'])
def test_unified_run_id_canonicalises_the_instant(stamp):
    assert keys.unified_run_id(H['x'], stamp) == GOLDEN['unified_run_id']


@pytest.mark.parametrize('stamp', ['2026-13-45T99:99:99Z', '２０２６-10-14T00:00:00Z', 'yesterday',
                                   '2026-10-14T12:00:00+01:00'], ids=['range', 'wide', 'text', 'offset'])
def test_unified_run_id_rejects_non_timestamps(stamp):
    with pytest.raises(ValueError):
        keys.unified_run_id(H['x'], stamp)


@pytest.mark.parametrize('version', ['n/a', 'none', '?', 'latest', 'Unknown', ' '],
                         ids=['na', 'none', 'q', 'latest', 'unk', 'blank'])
def test_placeholder_versions_are_not_cache_eligible(version):
    """F-15: the global IR cache must never be keyed by a placeholder version."""
    assert not keys.ir_cache_eligible(ir_inputs(ghidra=version))


RVAS = st.lists(st.integers(0, 2 ** 32 - 1), unique=True, max_size=6)
SOURCE_REFS = st.builds(
    SourceRef, source=st.sampled_from(['ghidriff', 'rz-diff', 'bindiff']),
    entry_id=st.text(alphabet=string.ascii_lowercase + string.digits + '-', min_size=1, max_size=12),
    file_sha256=st.one_of(st.none(), st.sampled_from(sorted(H.values()))), version=st.sampled_from(['1', '1.0.0', '2']))
ADDRESSES = st.integers(0, 2 ** 32).flatmap(lambda v: st.sampled_from([v, f'0x{v:X}', f' 0X{v:08x} ']))


@settings(max_examples=60, deadline=None)
@given(older=RVAS, newer=RVAS, seed=st.randoms(use_true_random=False))
def test_row_id_ignores_the_order_of_the_rva_lists(older, newer, seed):
    assume(older or newer)
    shuffled_older, shuffled_newer = list(older), list(newer)
    seed.shuffle(shuffled_older)
    seed.shuffle(shuffled_newer)
    assert keys.row_id(H['o'], H['n'], older, newer) == keys.row_id(H['o'], H['n'], shuffled_older, shuffled_newer)


@settings(max_examples=60, deadline=None)
@given(sources=st.lists(SOURCE_REFS, max_size=6), seed=st.randoms(use_true_random=False))
def test_source_set_digest_ignores_order_and_duplicates(sources, seed):
    shuffled = [*sources, *sources[:2]]  # a repeated source is one source
    seed.shuffle(shuffled)
    assert keys.source_set_digest(sources) == keys.source_set_digest(shuffled)


@settings(max_examples=60, deadline=None)
@given(corrections=st.lists(st.tuples(st.sampled_from(['matched', 'split', 'merged']),
                                      st.lists(ADDRESSES, max_size=4), st.lists(ADDRESSES, max_size=4)), max_size=4),
       seed=st.randoms(use_true_random=False))
def test_manual_digest_is_order_independent_for_mixed_int_and_text_addresses(corrections, seed):
    shuffled = [(category, list(older), list(newer)) for category, older, newer in corrections]
    for _category, older, newer in shuffled:
        seed.shuffle(older)
        seed.shuffle(newer)
    seed.shuffle(shuffled)
    assert keys.manual_digest(corrections) == keys.manual_digest(shuffled)


@settings(max_examples=60, deadline=None)
@given(value=st.integers(0, 2 ** 40))
def test_an_address_has_one_spelling(value):
    spellings = [value, hex(value), f'0x{value:X}', f' 0X{value:x} ', f'0x{value:016x}']
    assert len({keys.manual_digest([('matched', [s], [])]) for s in spellings}) == 1


def test_ir_key_inputs_enforce_producer_consistency():
    with pytest.raises(ValueError):
        ir_inputs(producer_kind='rizin', mode='gzf')
    for missing in ('script_sha256', 'analysis_options_digest'):  # two analyze runs must not share one key
        with pytest.raises(ValueError):
            ir_inputs(mode='analyze', **{missing: None})
    assert ir_inputs(producer_kind='binexport', mode='binexport', script_sha256=None,
                     analysis_options_digest=None).script_sha256 is None
