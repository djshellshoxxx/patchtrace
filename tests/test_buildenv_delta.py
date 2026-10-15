"""Toolchain verdict, unknown-versus-absent semantics and the noise map (DIE plan s6 and s7)."""
from __future__ import annotations

import typing

import pytest
from pe_build_fixtures import MSVC_RICH, BuildSpec, build_with_facts
from pydantic import ValidationError
from test_buildenv_support import (
    GOLDENS,
    LINUX_DB,
    WINDOWS_DB,
    detects,
    die_summary,
    evidence_of,
    fingerprint_of,
    pair_fingerprints,
)

from patchtrace.buildenv import noise_map
from patchtrace.buildenv.contracts import BuildChange, BuildEnvError
from patchtrace.buildenv.delta import compute_delta
from patchtrace.buildenv.fingerprint import build_fingerprint
from patchtrace.intelligence.tools.delta import quality_flags
from patchtrace.unified.contracts import ChangeClass

MSVC = ('compiler', 'Microsoft Visual C/C++', '19.38')
LINKER_14_38 = ('linker', 'Microsoft Linker', '14.38')
LINKER_14_40 = ('linker', 'Microsoft Linker', '14.40')


def pe(**kw) -> bytes:
    return build_with_facts(BuildSpec(**kw))


def delta_of(tmp_path, older_pe: bytes, newer_pe: bytes, older_die=None, newer_die=None, **kw):
    older = fingerprint_of(tmp_path, older_pe, 'older', older_die, **kw)
    newer = fingerprint_of(tmp_path, newer_pe, 'newer', newer_die, **kw)
    return compute_delta(older, newer)


def test_header_only_difference_is_unknown(tmp_path):
    delta = delta_of(tmp_path, pe(linker=(14, 36)), pe(linker=(2, 38)))
    assert delta.toolchain == 'unknown' and 'header-only' in delta.reasons
    assert next(c for c in delta.changes if c.key == 'linker_field').strength == 'weak'


def test_lld_style_header_has_no_rich_and_linker_14_0(tmp_path):
    fp = fingerprint_of(tmp_path, pe(rich=None, linker=(14, 0)), 'older')
    facts = {f.key: f for f in fp.facts}
    assert 'rich_signature' not in facts
    assert (facts['linker_field'].value, facts['linker_field'].certainty) == ('14.0', 'exact-field')
    assert all(f.certainty != 'signature' for f in fp.facts)  # a header field is never a brand


def test_rich_counts_alone_never_differ(tmp_path):
    counts = [(pid, build, count + 7) for pid, build, count in MSVC_RICH]
    delta = delta_of(tmp_path, pe(rich=MSVC_RICH), pe(rich=counts))
    change = next(c for c in delta.changes if c.key == 'rich_signature')
    assert change.change == 'unchanged' and delta.toolchain == 'same'


def test_valid_rich_pairs_differing_is_a_strong_difference(tmp_path):
    other = [(0x0105, 34000, 12), *MSVC_RICH[1:]]
    delta = delta_of(tmp_path, pe(rich=MSVC_RICH), pe(rich=other))
    assert delta.toolchain == 'differs'
    assert next(c for c in delta.changes if c.key == 'rich_signature').strength == 'strong'


def test_rich_absent_is_unknown(tmp_path):
    delta = delta_of(tmp_path, pe(rich=MSVC_RICH), pe(rich=None))
    change = next(c for c in delta.changes if c.key == 'rich_signature')
    assert (change.change, change.strength) == ('changed', 'weak') and delta.toolchain == 'unknown'


def test_rich_checksum_failure_is_weak(tmp_path):
    other = [(0x0105, 34000, 12), *MSVC_RICH[1:]]
    forged = bytearray(pe(rich=other))
    forged[0x44] ^= 0xFF  # a DOS stub byte inside the checksummed region
    delta = delta_of(tmp_path, pe(rich=MSVC_RICH), bytes(forged))
    change = next(c for c in delta.changes if c.key == 'rich_signature')
    assert change.change == 'changed' and change.strength == 'weak' and delta.toolchain == 'unknown'


def test_channels_contradict_downgrades_to_unknown(tmp_path):
    other = [(0x0105, 34000, 12), *MSVC_RICH[1:]]
    same_names = detects(MSVC, LINKER_14_38)
    delta = delta_of(tmp_path, pe(rich=MSVC_RICH), pe(rich=other), same_names, same_names)
    assert delta.toolchain == 'unknown' and 'sources-disagree' in delta.reasons
    assert any(w.code == 'sources-disagree' for w in delta.preflight)


def test_shared_origin_counts_once(tmp_path):
    older_die, newer_die = detects(MSVC, LINKER_14_38), detects(MSVC, LINKER_14_40)
    delta = delta_of(tmp_path, pe(rich=None, linker=(14, 38)), pe(rich=None, linker=(14, 40)), older_die, newer_die)
    assert delta.toolchain == 'differs' and not delta.toolchain_corroborated  # diec linker name + header field = 1
    other = [(0x0105, 34000, 12), *MSVC_RICH[1:]]
    delta = delta_of(tmp_path, pe(rich=MSVC_RICH, linker=(14, 38)), pe(rich=other, linker=(14, 40)),
                     older_die, newer_die)
    assert delta.toolchain == 'differs' and delta.toolchain_corroborated


def test_one_sided_is_unknown_not_difference(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-unknown', 'unknown')
    delta = compute_delta(older, newer)
    one_sided = {c.key for c in delta.changes if c.change == 'one-sided-unknown'}
    assert {'compiler', 'linker', 'build_tool'} <= one_sided and delta.toolchain == 'unknown'


def test_heuristic_detections_never_form_a_difference(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain', heuristics=True)
    assert any(f.certainty == 'heuristic' for f in newer.facts)
    delta = compute_delta(older, newer)
    assert delta.toolchain == 'differs'  # decided by the signature compiler change alone
    assert all(c.key != 'protector' for c in delta.changes)  # `(Heur)Protection: Generic` is not compared


def test_stale_evidence_is_reference_only(tmp_path):
    older = fingerprint_of(tmp_path, pe(), 'older', detects(MSVC), db=LINUX_DB)
    newer = fingerprint_of(tmp_path, pe(linker=(14, 40)), 'newer', detects(('compiler', 'MinGW', '10')), db=WINDOWS_DB)
    delta = compute_delta(older, newer)
    assert delta.toolchain == 'unknown' and 'die-versions-differ' in delta.reasons
    assert any(w.code == 'stale-evidence' for w in delta.preflight)
    assert all('diec' not in c.basis for c in delta.changes)


def test_foreign_evidence_is_rejected_at_the_fingerprint():
    sha = '0' * 64
    with pytest.raises(BuildEnvError) as excinfo:
        build_fingerprint(sha, 'older', die=die_summary('older', sha),
                          evidence=evidence_of(detects(MSVC), 'older', '1' * 64))
    assert excinfo.value.code == 'PT-BUILD-STALE'
    with pytest.raises(BuildEnvError) as excinfo:
        build_fingerprint(sha, 'older', die=die_summary('older', sha))
    assert excinfo.value.code == 'PT-BUILD-INPUT'


def test_swapped_arguments_are_a_mismatch(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-same', 'same')
    with pytest.raises(BuildEnvError) as excinfo:
        compute_delta(newer, older)
    assert excinfo.value.code == 'PT-BUILD-MISMATCH'


def test_swapping_orientation_inverts_every_change(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain')
    forward = compute_delta(older, newer)
    back = compute_delta(newer.model_copy(update={'side': 'older'}), older.model_copy(update={'side': 'newer'}))
    flipped = {'added': 'removed', 'removed': 'added'}
    for a, b in zip(sorted(forward.changes, key=lambda c: c.key), sorted(back.changes, key=lambda c: c.key),
                    strict=True):
        assert (a.older, a.newer) == (b.newer, b.older) and flipped.get(a.change, a.change) == b.change
    assert forward.toolchain == back.toolchain


def test_delta_is_idempotent_and_identified_by_both_ids(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain')
    first, second = compute_delta(older, newer), compute_delta(older, newer)
    assert first == second and first.model_dump_json() == second.model_dump_json()
    plain_older, plain_newer = pair_fingerprints(tmp_path, 'diec-toolchain')
    assert compute_delta(plain_older, plain_newer).delta_id != first.delta_id


@pytest.mark.parametrize('pair', ['diec-toolchain', 'diec-same', 'diec-unknown'], ids=['toolchain', 'same', 'unknown'])
def test_without_die_nothing_is_ever_a_difference_from_headers_alone(tmp_path, pair):
    older, newer = pair_fingerprints(tmp_path, pair)
    delta = compute_delta(older, newer)
    assert delta.toolchain != 'differs'  # these pairs differ in forgeable fields and an optional Rich header only


def test_option_changes_are_context_only(tmp_path):
    delta = delta_of(tmp_path, pe(load_config=(0x1000, 0x100)), pe(load_config=(0x1000, 0)))
    assert delta.options_changed == ('cfg',) and delta.toolchain == 'unknown' and delta.noise == ()


def test_presence_facts_need_both_channels_to_have_run(tmp_path):
    clr = pe(clr_flags=1)
    delta = delta_of(tmp_path, clr, pe())
    assert next(c for c in delta.changes if c.key == 'managed').change == 'removed'
    older, newer = pair_fingerprints(tmp_path, 'diec-unknown', 'unknown')
    assert next(c for c in compute_delta(older, newer).changes if c.key == 'compiler').change == 'one-sided-unknown'


@pytest.mark.parametrize('pair,kind,expected', [('diec-toolchain', 'toolchain', True), ('diec-same', 'same', False),
                                               ('diec-unknown', 'unknown', False)], ids=['swap', 'same', 'unknown'])
def test_quality_flags_parity(tmp_path, pair, kind, expected):
    """`delta.quality_flags` (T6.4) and `BuildEnvDelta.toolchain` agree on the committed goldens."""
    older, newer = pair_fingerprints(tmp_path, pair, kind)
    evidence = tuple(evidence_of((GOLDENS / f'diec-{kind}-{side}.json').read_bytes(), side, 'b' * 64)
                     for side in ('older', 'newer'))
    flagged = any(f.code == 'toolchain-changed' for f in quality_flags(diec=evidence))
    assert flagged == expected == (compute_delta(older, newer).toolchain == 'differs')


# --- noise map ---------------------------------------------------------------------------------------------

def row(verdict='review', classes=('eh',), omitted=0, limits=(), group='review') -> noise_map.RowFacts:
    return noise_map.RowFacts('r', group, verdict, tuple(classes), omitted, tuple(limits))


def test_the_map_covers_every_change_class_exactly_once():
    classes = set(typing.get_args(ChangeClass))
    mapped, never = set(noise_map.NOISE_MAP), set(noise_map.NEVER_CLASSES)
    assert mapped | never == classes and not mapped & never


@pytest.mark.parametrize('cls', sorted(noise_map.NEVER_CLASSES))
def test_semantic_classes_are_never_tagged(cls):
    assert noise_map.row_effect(row(classes=(cls,)), 'differs') is None
    assert noise_map.row_effect(row(classes=('eh', cls)), 'differs') is None


@pytest.mark.parametrize('verdict', ['material', 'unchanged', 'cosmetic', 'unknown'])
def test_material_and_other_verdicts_are_never_tagged(verdict):
    assert noise_map.row_effect(row(verdict=verdict), 'differs') is None


def test_rows_with_omitted_deltas_or_limits_are_never_tagged():
    assert noise_map.row_effect(row(omitted=1), 'differs') is None
    assert noise_map.row_effect(row(limits=('deltas-cap',)), 'differs') is None


@pytest.mark.parametrize('toolchain', ['same', 'unknown'])
def test_no_tag_unless_the_toolchain_differs(toolchain):
    assert noise_map.row_effect(row(), toolchain) is None


def test_effects_and_mixed_rows_take_the_weakest():
    assert noise_map.row_effect(row(classes=('frame',)), 'differs') == 'order'
    assert noise_map.row_effect(row(classes=('cfg',)), 'differs') == 'tag'
    assert noise_map.row_effect(row(classes=('frame', 'cfg')), 'differs') == 'tag'
    assert noise_map.row_effect(row(classes=()), 'differs') is None


def test_ordering_never_crosses_a_group_and_is_stable():
    rows = [noise_map.RowFacts(f'{g}{i}', g, 'review', ('eh',)) for g in ('a', 'b') for i in range(3)]
    tags = {'a0': 'order', 'b1': 'order'}
    assert noise_map.order_rows(rows, tags) == ['a1', 'a2', 'a0', 'b0', 'b2', 'b1']


def test_tagged_rows_are_a_subset_of_qualifying_rows():
    rows = [row(classes=c) for c in (('eh',), ('constant',), ('cfg',), ())]
    tags = noise_map.tag_rows([noise_map.RowFacts(f'r{i}', 'g', 'review', r.classes) for i, r in enumerate(rows)],
                              'differs')
    assert set(tags) == {'r0', 'r2'}


def test_noise_reasons_exist_only_for_a_difference():
    assert noise_map.noise_reasons('same') == () and noise_map.noise_reasons('unknown') == ()
    reasons = noise_map.noise_reasons('differs')
    assert {r.effect for r in reasons} == {'order', 'tag'}
    assert set(sum((r.classes for r in reasons), ())) == set(noise_map.NOISE_MAP)


# --- contracts ---------------------------------------------------------------------------------------------

def test_change_validator_rejects_inconsistent_values():
    base = {'key': 'compiler', 'older': 'a', 'newer': 'b', 'change': 'unchanged', 'kind': 'toolchain',
            'strength': 'weak', 'basis': ()}
    with pytest.raises(ValidationError):
        BuildChange(**base)
    with pytest.raises(ValidationError):
        BuildChange(**{**base, 'change': 'added'})
    with pytest.raises(ValidationError):
        BuildChange(**{**base, 'surprise': 1, 'change': 'changed'})


def test_records_are_frozen_and_round_trip(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain')
    delta = compute_delta(older, newer)
    with pytest.raises(ValidationError):
        delta.toolchain = 'same'
    assert type(delta).model_validate_json(delta.model_dump_json()) == delta
    assert type(older).model_validate_json(older.model_dump_json()) == older
