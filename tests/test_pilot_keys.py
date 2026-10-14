"""PIL-A1 identities, origin components and ports (docs/specs/program-e/PIL-integration-plan.md s4, s7, s9).

Covers: `candidate_key` parity with `unified.keys.row_id`, input coverage and determinism of `result_id` (across
processes and hash seeds), observation ids, config/limits digests, self-certifying verification helpers, the
shared-origin component calculus (permutation invariant, idempotent, never raised by a known tag), and that
`ports.py` holds Protocols only. Synthetic data only; nothing here is live evidence.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from patchtrace.enrichment.identity import canonical_json
from patchtrace.pilot import keys, origins, ports
from patchtrace.pilot.contracts import (
    LeadCounts,
    Nav,
    ObsRef,
    PilotAssessment,
    PilotConfig,
    PilotInputs,
    PilotManifest,
    PilotResultPointer,
    ToolKey,
)
from patchtrace.pilot.limits import DEFAULT_LIMITS, PilotError, PilotLimits
from patchtrace.unified import keys as unified_keys

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / 'docs' / 'schemas' / 'pilot' / 'examples'
H = {k: hashlib.sha256(k.encode()).hexdigest() for k in (
    'o', 'n', 'raw', 'uni', 's1', 's2', 'tc', 'tk', 'fx', 'fy', 'kev', 'kb', 'lex', 'rules', 'prules', 'orig', 'cfg',
    'x', 'y')}
PROPS = settings(deadline=None, max_examples=80, derandomize=True, database=None,
                 suppress_health_check=[HealthCheck.too_slow])


def descending(*values: str) -> tuple[str, ...]:
    """A deliberately non-canonical order, independent of the digest values."""
    return tuple(sorted(values, reverse=True))


def inputs(**over) -> PilotInputs:
    data = dict(older_sha256=H['o'], newer_sha256=H['n'], ghidriff_run_id='run-1', raw_sha256=H['raw'],
                unified_result_id=H['uni'], secondary_set_ids=tuple(sorted((H['s1'], H['s2']))),
                tool_keys=(ToolKey(engine='capa', side='newer', cache_key=H['tk']),
                           ToolKey(engine='capa', side='older', cache_key=H['tc'])),
                advisory_facts_ids=(H['fx'],), kev_snapshot_id=H['kev'], kb_link_digest=H['kb'],
                asserted_gates=('CVE-2099-20001',), lexicon_digest=H['lex'], rules_digest=H['rules'],
                pilot_rules_digest=H['prules'], origins_digest=H['orig'], tiers_version=1, config_digest=H['cfg'])
    data.update(over)
    return PilotInputs(**data)


# --- candidate_key: the unified row identity, re-derived without importing another feature ----------------------

def test_candidate_key_equals_the_unified_row_id():
    for older, newer in (([16, 32], [48]), ([4096], [4368]), ([7], []), ([], [9])):
        assert keys.candidate_key(H['o'], H['n'], older, newer) == unified_keys.row_id(H['o'], H['n'], older, newer)


def test_candidate_key_follows_the_documented_domain_formula():
    expected = hashlib.sha256(b'patchtrace\x00unified-row\x001\x00' + canonical_json(
        {'older_sha256': H['o'], 'newer_sha256': H['n'], 'older_rvas': [16, 32], 'newer_rvas': [48]})).hexdigest()
    assert keys.candidate_key(H['o'], H['n'], [32, 16], [48]) == expected


def test_candidate_key_changes_with_orientation_and_ignores_rva_order():
    base = keys.candidate_key(H['o'], H['n'], [16, 32], [48])
    assert keys.candidate_key(H['n'], H['o'], [16, 32], [48]) != base
    assert keys.candidate_key(H['o'], H['n'], [48], [16, 32]) != base
    assert keys.candidate_key(H['o'], H['n'], [32, 16], [48]) == base


@pytest.mark.parametrize('bad', [([1, 1], [2]), ([-1], [2]), ([2**32], [1]), ([True], [1]), ([], [])],
                         ids=['dup', 'neg', 'big', 'bool', 'empty'])
def test_candidate_key_rejects_bad_rvas(bad):
    with pytest.raises(ValueError):
        keys.candidate_key(H['o'], H['n'], *bad)


# --- result_id ------------------------------------------------------------------------------------------------

def test_result_id_follows_the_documented_domain_formula():
    payload = inputs().model_dump(mode='json')
    expected = hashlib.sha256(b'patchtrace\x00pilot-result\x001\x00' + canonical_json(payload)).hexdigest()
    assert keys.result_id(inputs()) == expected


CHANGES = {
    'older_sha256': H['x'], 'newer_sha256': H['x'], 'orientation': None, 'ghidriff_run_id': 'run-2',
    'raw_sha256': H['x'], 'unified_result_id': None, 'secondary_set_ids': (H['s1'],),
    'tool_keys': (ToolKey(engine='capa', side='newer', cache_key=H['tk']),),
    'advisory_facts_ids': tuple(sorted((H['fx'], H['fy']))),
    'kev_snapshot_id': None, 'kb_link_digest': None, 'asserted_gates': (), 'lexicon_digest': H['x'],
    'rules_digest': H['x'], 'pilot_rules_digest': H['x'], 'origins_digest': H['x'], 'tiers_version': 2,
    'config_digest': H['x']}


def test_every_result_input_is_covered_and_nothing_else():
    """The identity payload is exactly the s7 list: reviews, timestamps and paths are never hashed."""
    assert set(PilotInputs.model_fields) == set(CHANGES)
    banned = ('created', 'utc', 'path', 'review', 'note', 'pin', 'time')
    assert not [f for f in PilotInputs.model_fields if any(b in f for b in banned)]


@pytest.mark.parametrize('field', sorted(f for f in CHANGES if f != 'orientation'),
                         ids=[f'f{i}' for i in range(len(CHANGES) - 1)])
def test_result_id_changes_with_every_input(field):
    base = inputs()
    changed = inputs(**{field: CHANGES[field]})
    assert keys.result_id(changed) != keys.result_id(base)
    assert keys.changed_inputs(base, changed) == (field,)


def test_orientation_swap_changes_the_result_id():
    assert keys.result_id(inputs(older_sha256=H['n'], newer_sha256=H['o'])) != keys.result_id(inputs())
    with pytest.raises(ValueError):
        inputs(orientation='newer->older')


def test_unchanged_inputs_report_no_change_and_set_inputs_must_be_canonical():
    assert keys.changed_inputs(inputs(), inputs()) == ()
    for bad in (dict(secondary_set_ids=descending(H['s1'], H['s2'])),
                dict(advisory_facts_ids=descending(H['fx'], H['fy'])),
                dict(asserted_gates=('CVE-2099-20002', 'CVE-2099-20001')),
                dict(tool_keys=(ToolKey(engine='capa', side='older', cache_key=H['tc']),
                                ToolKey(engine='capa', side='newer', cache_key=H['tk']))),
                dict(secondary_set_ids=(H['s1'], H['s1']))):
        with pytest.raises(ValueError):
            inputs(**bad)


# --- limits and config digests -----------------------------------------------------------------------------------

def test_limits_digest_changes_with_any_limit_and_is_stable():
    base = keys.limits_digest()
    assert base == keys.limits_digest(DEFAULT_LIMITS)
    for name in DEFAULT_LIMITS.as_dict():
        value = getattr(DEFAULT_LIMITS, name)
        other = PilotLimits(**{**DEFAULT_LIMITS.as_dict(), name: value - 1 if value > 1 else value + 1})
        assert keys.limits_digest(other) != base, name


def test_config_digest_covers_every_knob_and_the_limits():
    base = keys.default_config()
    assert base.limits_digest == keys.limits_digest()
    digest = keys.config_digest(base)
    for over in (dict(locality_min_tokens=3), dict(confounded_min_cves=3), dict(lexical_moderate=False),
                 dict(limits_digest=H['x'])):
        assert keys.config_digest(base.model_copy(update=over)) != digest
    assert set(PilotConfig.model_fields) == {'locality_min_tokens', 'confounded_min_cves', 'lexical_moderate',
                                              'limits_digest'}
    assert keys.default_config(locality_min_tokens=3).locality_min_tokens == 3


def test_default_config_matches_the_plan_defaults():
    config = keys.default_config()
    assert (config.locality_min_tokens, config.confounded_min_cves, config.lexical_moderate) == (2, 2, True)


# --- observation ids ---------------------------------------------------------------------------------------------

OBS = dict(channel='code', kind='loc:names', role='local', verification='label-only', origins=('D_symbols',),
           evidence_class='E-NAME', obligations=(), anchor_ids=(), ref=ObsRef(kind='name-tokens', id='fragment+reassemble'),
           nav=Nav(side='newer', rva=0x1000, start_line=3, end_line=4), detail='names share two tokens')
OBS_CHANGES = {
    'channel': 'advisory', 'kind': 'loc:string', 'role': 'context', 'verification': 'advisory-claim',
    'origins': ('D_bytes',), 'evidence_class': 'E-DATA', 'obligations': ('guard-dominates-sink',),
    'anchor_ids': ('fn:abc',), 'ref': ObsRef(kind='name-tokens', id='other'), 'nav': None, 'detail': 'other text'}


def test_observation_id_covers_every_field_and_is_certified():
    base = keys.make_observation(**OBS)
    assert base.obs_id == keys.observation_id(base)
    assert set(OBS_CHANGES) == set(OBS)
    for field, value in OBS_CHANGES.items():
        changed = keys.make_observation(**{**OBS, field: value})
        assert changed.obs_id != base.obs_id, field
    assert keys.make_observation(**OBS) == base  # same content, same id: duplicates are idempotent


def test_observation_id_uses_its_own_domain():
    obs = keys.make_observation(**OBS)
    payload = obs.model_dump(mode='json')
    del payload['obs_id']
    assert obs.obs_id == hashlib.sha256(b'patchtrace\x00pilot-obs\x001\x00' + canonical_json(payload)).hexdigest()


# --- canonical bytes, entry ids and paths -----------------------------------------------------------------------

def _example(name: str):
    return (EXAMPLES / name).read_text(encoding='utf-8')


def test_canonical_bytes_are_sorted_compact_utf8_and_round_trip():
    assessment = PilotAssessment.model_validate_json(_example('valid-PilotAssessment.json'))
    data = keys.canonical_bytes(assessment)
    assert data == canonical_json(assessment.model_dump(mode='json'))
    independent = json.dumps(assessment.model_dump(mode='json'), sort_keys=True, separators=(',', ':'),
                             ensure_ascii=False, allow_nan=False).encode('utf-8')
    assert data == independent and b'\n' not in data
    assert PilotAssessment.model_validate_json(data) == assessment
    assert keys.content_sha256(assessment) == hashlib.sha256(data).hexdigest()


def test_entry_ids_and_sidecar_paths_are_short_and_stable():
    rid = H['x']
    assert keys.KIND == 'patch-intent'
    assert keys.pointer_entry_id(rid) == f'pilot-result:{rid}'
    assert keys.relative_dir(rid) == f'intelligence/pilot/{rid[:16]}'
    assert keys.review_entry_id('0a1b2c3d-0000-4000-8000-000000000001') == \
        'pilot-review:0a1b2c3d-0000-4000-8000-000000000001'
    for bad in ('not-a-uuid', '0A1B2C3D-0000-4000-8000-000000000001', ''):
        with pytest.raises(ValueError):
            keys.review_entry_id(bad)
    longest = f'{keys.relative_dir(rid)}/{max(keys.MANIFEST_NAME, keys.ASSESSMENT_NAME, key=len)}'
    assert len(longest) <= 120  # Windows: sidecar paths of 120 characters or fewer (s7)


def test_guard_parts_follow_the_documented_tuple():
    assert keys.guard_parts('proj-1', inputs()) == ('proj-1', 'run-1', H['raw'], keys.result_id(inputs()))


# --- verification helpers (a record certifies its own ids) -------------------------------------------------------

@pytest.fixture
def chain():
    assessment = PilotAssessment.model_validate_json(_example('valid-PilotAssessment.json'))
    manifest = PilotManifest.model_validate_json(_example('valid-PilotManifest.json'))
    pointer = PilotResultPointer.model_validate_json(_example('valid-PilotResultPointer.json'))
    return assessment, manifest, pointer


def test_the_committed_examples_form_a_certified_chain(chain):
    assessment, manifest, pointer = chain
    keys.verify_assessment(assessment)
    keys.verify_manifest(manifest, assessment)
    keys.verify_pointer(pointer, manifest)
    assert keys.make_manifest(assessment, keys.default_config(), created_utc=manifest.created_utc) == manifest
    assert keys.make_pointer(manifest) == pointer
    assert assessment.lead_counts() == manifest.counts == pointer.counts


def _raises(code_reason, fn, *args):
    with pytest.raises(PilotError) as info:
        fn(*args)
    assert (info.value.code, info.value.reason) == code_reason


def test_verify_assessment_detects_a_tampered_result_id_or_observation(chain):
    assessment, _, _ = chain
    _raises(('PT-PILOT-INTEGRITY', 'result-id'), keys.verify_assessment,
            assessment.model_copy(update={'result_id': H['x']}))
    swapped = assessment.inputs.model_copy(update={'raw_sha256': H['x']})
    _raises(('PT-PILOT-INTEGRITY', 'result-id'), keys.verify_assessment,
            assessment.model_copy(update={'inputs': swapped}))
    pool = list(assessment.observations)
    pool[0] = pool[0].model_copy(update={'detail': 'tampered text'})
    _raises(('PT-PILOT-INTEGRITY', 'observation-id'), keys.verify_assessment,
            assessment.model_copy(update={'observations': tuple(pool)}))


def test_verify_manifest_and_pointer_detect_drift(chain):
    assessment, manifest, pointer = chain
    _raises(('PT-PILOT-INTEGRITY', 'result-id'), keys.verify_manifest, manifest.model_copy(update={'result_id': H['x']}),
            assessment)
    part = manifest.parts[0].model_copy(update={'sha256': H['x']})
    _raises(('PT-PILOT-INTEGRITY', 'part-digest'), keys.verify_manifest,
            manifest.model_copy(update={'parts': (part,)}), assessment)
    _raises(('PT-PILOT-INTEGRITY', 'counts'), keys.verify_manifest,
            manifest.model_copy(update={'counts': LeadCounts(fit=9, review=0, partial=0, code=0, queue=0)}),
            assessment)
    config = manifest.config.model_copy(update={'locality_min_tokens': 5})
    _raises(('PT-PILOT-INTEGRITY', 'config-digest'), keys.verify_manifest,
            manifest.model_copy(update={'config': config}), assessment)
    _raises(('PT-PILOT-INTEGRITY', 'manifest-digest'), keys.verify_pointer,
            pointer.model_copy(update={'manifest_sha256': H['x']}), manifest)
    _raises(('PT-PILOT-INTEGRITY', 'pointer'), keys.verify_pointer,
            pointer.model_copy(update={'status': 'partial'}), manifest)


# --- determinism across processes and hash seeds -----------------------------------------------------------------

def test_keys_are_identical_across_processes_and_hash_seeds():
    code = ('import json, hashlib\nfrom patchtrace.pilot import keys, origins\n'
            'from patchtrace.pilot.contracts import PilotInputs, ObsRef\n'
            'h = lambda k: hashlib.sha256(k.encode()).hexdigest()\n'
            'inp = PilotInputs(older_sha256=h("o"), newer_sha256=h("n"), ghidriff_run_id="r", raw_sha256=h("r"), '
            'secondary_set_ids=tuple(sorted({h("a"), h("b"), h("c")})), asserted_gates=("CVE-2099-20001",), '
            'lexicon_digest=h("l"), rules_digest=h("u"), pilot_rules_digest=h("p"), origins_digest=origins.digest(), '
            'tiers_version=1, config_digest=keys.config_digest(keys.default_config()))\n'
            'obs = keys.make_observation(channel="code", kind="b1:BND", role="shape", verification="tool-reported", '
            'origins=("D_ghidra",), evidence_class="E-DECOMP", ref=ObsRef(kind="b1-signal", id="s"), '
            'detail="bounds check added")\n'
            'comps = origins.components([{"D_b", "D_a"}, {"D_c"}, {"D_a", "D_d"}])\n'
            'print(json.dumps([keys.result_id(inp), keys.limits_digest(), obs.obs_id, origins.digest(), '
            'keys.candidate_key(h("o"), h("n"), [3, 1, 2], [9]), comps]))\n')
    outputs = set()
    for seed in ('1', '2', '3'):
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'), PYTHONHASHSEED=seed)
        result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env)
        assert result.returncode == 0, result.stderr
        outputs.add(result.stdout.strip())
    assert len(outputs) == 1
    assert json.loads(outputs.pop())[1] == keys.limits_digest(DEFAULT_LIMITS)


def test_every_identity_domain_used_is_declared(monkeypatch):
    seen: list[str] = []
    real = keys.domain_id

    def spy(domain, version, payload):
        seen.append(domain)
        return real(domain, version, payload)
    monkeypatch.setattr(keys, 'domain_id', spy)
    monkeypatch.setattr(origins, 'domain_id', spy)
    keys.limits_digest()
    keys.config_digest(keys.default_config())
    keys.result_id(inputs())
    keys.candidate_key(H['o'], H['n'], [1], [2])
    keys.make_observation(**OBS)
    origins.digest()
    assert set(seen) == set(keys.DOMAINS)
    assert keys.DOMAINS == ('pilot-result', 'pilot-config', 'pilot-limits', 'pilot-obs', 'pilot-origins',
                            'unified-row')


# --- origins: shared origin counts once --------------------------------------------------------------------------

def test_one_origin_family_is_one_component():
    reg = origins.DefaultOriginRegistry()
    advisory = [reg.tags_for(s) for s in ('advisory-text', 'nvd-cwe', 'msrc-cwe', 'kev-cwe')]
    assert len(reg.components(advisory)) == 1  # three more advisory sources add no independence
    code = [reg.tags_for(s) for s in ('b1', 'change-facts', 'call-label')]
    assert len(reg.components(code)) == 1  # B1, ChangeFacts and Ghidriff labels are all Ghidra-derived
    assert reg.tags_for('capa-ghidra') == reg.tags_for('b1')


def test_independent_origins_are_separate_components():
    reg = origins.DefaultOriginRegistry()
    sets = [reg.tags_for(s) for s in ('advisory-text', 'b1', 'pe-import', 'capa', 'floss')]
    comps = reg.components(sets)
    assert [c[0] for c in comps] == sorted({'D_vendor_text', 'D_ghidra', 'D_pe_tables', 'D_vivisect', 'D_bytes'})
    assert origins.lead_components(sets).count == 5


def test_transitive_sharing_merges_components():
    comps = origins.components([{'D_a', 'D_b'}, {'D_b', 'D_c'}, {'D_d'}, {'D_e', 'D_d'}])
    assert comps == (('D_a', 'D_b', 'D_c'), ('D_d', 'D_e'))
    summary = origins.lead_components([{'D_a', 'D_b'}, {'D_b', 'D_c'}, {'D_d'}])
    assert (summary.count, summary.tags) == (2, ('D_a', 'D_d'))


def test_components_reject_unsafe_input():
    for bad in ([set()], ['D_ghidra'], [{'ghidra'}], [{'D_ok', 'D_Bad'}], [{'D_' + 'x' * 40}]):
        with pytest.raises((ValueError, TypeError)):
            origins.components(bad)
    assert origins.components([]) == ()


def test_unknown_origin_source_fails_closed():
    with pytest.raises(PilotError) as info:
        origins.DefaultOriginRegistry().tags_for('mystery-engine')
    assert info.value.code == 'PT-PILOT-INPUT' and info.value.reason == 'unknown-origin-source'


def test_origins_digest_tracks_the_table_and_version():
    base = origins.DefaultOriginRegistry()
    assert base.digest() == origins.digest()
    table = {k: tuple(v) for k, v in origins.SOURCE_TAGS.items()}
    table['b1'] = ('D_ghidra', 'D_symbols')
    assert origins.DefaultOriginRegistry(table).digest() != base.digest()
    assert origins.DefaultOriginRegistry(version=origins.ORIGINS_VERSION + 1).digest() != base.digest()
    assert set(t for tags in origins.SOURCE_TAGS.values() for t in tags) <= set(origins.TAGS)
    assert all(tags == tuple(sorted(set(tags))) for tags in origins.SOURCE_TAGS.values())


TAGS = ['D_a', 'D_b', 'D_c', 'D_d', 'D_e', 'D_f']
TAG_SETS = st.lists(st.frozensets(st.sampled_from(TAGS), min_size=1, max_size=3), min_size=0, max_size=8)


@PROPS
@given(TAG_SETS, st.randoms(use_true_random=False))
def test_components_are_permutation_invariant(sets, rnd):
    shuffled = list(sets)
    rnd.shuffle(shuffled)
    assert origins.components(sets) == origins.components(shuffled)


@PROPS
@given(TAG_SETS)
def test_duplicate_origin_sets_are_idempotent(sets):
    assert origins.components(sets + sets) == origins.components(sets)


@PROPS
@given(TAG_SETS, st.frozensets(st.sampled_from(TAGS), min_size=1, max_size=3))
def test_an_observation_with_known_origins_never_raises_the_component_count(sets, extra):
    assume(sets and extra <= frozenset().union(*sets))
    assert len(origins.components([*sets, extra])) <= len(origins.components(sets))


@PROPS
@given(TAG_SETS)
def test_components_partition_the_tags_and_contain_every_input_set(sets):
    comps = origins.components(sets)
    flat = [t for c in comps for t in c]
    assert len(flat) == len(set(flat)) == len(frozenset().union(*sets)) if sets else not comps
    assert list(comps) == sorted(comps) and all(list(c) == sorted(c) for c in comps)
    for tag_set in sets:
        assert sum(1 for c in comps if tag_set <= set(c)) == 1


# --- ports: Protocols only -----------------------------------------------------------------------------------------

PORT_NAMES = ('OriginRegistry', 'AnchorSink', 'Navigator', 'AdvisorySource', 'ChangeEvidenceSource',
              'ToolEvidenceSource', 'KevSource', 'CallDeltaSource', 'PairingSource')


def test_ports_module_defines_exactly_the_planned_protocols():
    defined = {n for n, v in vars(ports).items() if isinstance(v, type) and v.__module__ == ports.__name__}
    assert defined == set(PORT_NAMES)
    for name in PORT_NAMES:
        assert getattr(getattr(ports, name), '_is_protocol', False), name


def test_ports_contain_no_behaviour():
    tree = ast.parse(Path(ports.__file__).read_text(encoding='utf-8'))  # the module under test, wherever it is imported
    assert not [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            body = [b for b in node.body if not (isinstance(b, ast.Expr) and isinstance(b.value, ast.Constant))]
            assert not body, f'{node.name} has behaviour; ports are Protocols only'


class _FakeNavigator:
    def unavailable_reason(self, candidate_key, nav):
        return 'no-match'

    def go(self, candidate_key, nav):
        return False


class _FakeSink:
    def publish(self, project_key, anchors):
        return None


class _FakeKev:
    def lookup(self, cve):
        return None

    def snapshot_id(self):
        return None


def test_protocols_are_structural_and_the_default_registry_satisfies_its_port():
    assert isinstance(origins.DefaultOriginRegistry(), ports.OriginRegistry)
    assert isinstance(_FakeNavigator(), ports.Navigator) and isinstance(_FakeSink(), ports.AnchorSink)
    assert isinstance(_FakeKev(), ports.KevSource)
    assert not isinstance(object(), ports.Navigator) and not isinstance(_FakeKev(), ports.PairingSource)
