"""View model states B0-B9, banners, copy deck, provenance, anchors and adapters (DIE plan s6, s8)."""
from __future__ import annotations

import typing

import pytest
from pe_build_fixtures import MSVC_RICH, BuildSpec, build_with_facts
from test_buildenv_support import LINUX_DB, detects, fingerprint_of, pair_fingerprints

from patchtrace.buildenv import copy
from patchtrace.buildenv.adapters import die_summary_from
from patchtrace.buildenv.anchors import ANCHOR_KEYS, anchors_for
from patchtrace.buildenv.contracts import FactKey
from patchtrace.buildenv.delta import compute_delta
from patchtrace.buildenv.view_model import banner_views, build_view, reading_view
from patchtrace.intelligence.tools.common import ToolManifest, ToolRun
from patchtrace.secondary.evidence_view import BANNED


@pytest.fixture
def swap(tmp_path):
    older, newer = pair_fingerprints(tmp_path, 'diec-toolchain', 'toolchain')
    return older, newer, compute_delta(older, newer)


def test_state_texts_are_the_spec_copy():
    assert build_view(None, None, None, project_open=False).state_text == 'Open a project to see the build environment.'
    assert reading_view('newer', 1, 2).state_text == 'Reading build environment: NEWER (1 of 2)...'
    assert build_view(None, None, None, error_code='PT-BUILD-INPUT').state_text == (
        'Build environment could not be read (PT-BUILD-INPUT). Earlier results are unchanged.')
    assert build_view(None, None, None, unsupported_version='3.20').state_text.startswith(
        'Detect It Easy 3.20 is not supported by this PatchTrace build (accepted: 3.21).')


def test_toolchain_states(tmp_path, swap):
    older, newer, delta = swap
    differs = build_view(older, newer, delta)
    assert differs.state == 'B4' and 'Microsoft Visual C/C++ 19.38.33134 -> MinGW' in differs.state_text
    assert "Matching rows are marked 'Build differs'; none are hidden." in differs.state_text
    same_o, same_n = pair_fingerprints(tmp_path, 'diec-same', 'same')
    assert build_view(same_o, same_n, compute_delta(same_o, same_n)).state == 'B3'
    unk_o, unk_n = pair_fingerprints(tmp_path, 'diec-unknown', 'unknown')
    unknown = build_view(unk_o, unk_n, compute_delta(unk_o, unk_n))
    assert unknown.state == 'B5' and 'Unknown is not treated as a difference.' in unknown.state_text
    plain_o, plain_n = pair_fingerprints(tmp_path, 'diec-unknown')
    assert build_view(plain_o, plain_n, compute_delta(plain_o, plain_n)).state == 'B2'


def test_incomplete_and_stale_states(swap):
    older, newer, delta = swap
    missing = build_view(older, None, None)
    assert missing.state == 'B6' and 'NEWER' in missing.state_text and missing.rows == ()
    stale = build_view(older, newer, delta, stale=True)
    assert stale.state == 'B7' and stale.rows and 'shown for reference only' in stale.state_text
    assert build_view(None, None, None, stale=True).state == 'B7'
    bare = newer.model_copy(update={'pe': None, 'die': None, 'facts': ()})  # a side whose file could not be read
    partial = build_view(older, bare, compute_delta(older, bare))
    assert partial.state == 'B6' and 'NEWER' in partial.state_text and partial.rows


def test_banner_not_colour_only(swap):
    delta = swap[2]
    banners = banner_views(delta)
    assert banners and all(b.text.startswith(b.glyph) and b.glyph in ('[!]', '[i]') for b in banners)
    assert all(b.text.startswith('[!] Caution:' if b.severity == 'caution' else '[i] Notice:') for b in banners)
    assert all(b.text.isascii() for b in banners)


def test_dismiss_scoped_to_delta(tmp_path, swap):
    older, newer, delta = swap
    assert banner_views(delta, delta.delta_id) == ()
    other = compute_delta(*pair_fingerprints(tmp_path, 'diec-toolchain'))  # same files, different tool evidence
    assert other.delta_id != delta.delta_id and banner_views(other, delta.delta_id)


def test_rows_provenance_and_technical(tmp_path, swap):
    older, newer, delta = swap
    view = build_view(older, newer, delta)
    assert view.rows[0].status in ('changed', 'added', 'removed') and len(view.rows) <= 128
    assert [r.status for r in view.rows] == sorted((r.status for r in view.rows),
                                                   key=['changed', 'added', 'removed', 'unknown (one side)',
                                                        'same'].index)
    assert 'Detect It Easy 3.21, signature' in next(r for r in view.rows if r.key == 'compiler').basis
    assert LINUX_DB[:16] in view.provenance and '3.21 linux deb' in view.provenance  # test_provenance_names_database
    assert copy.DISCLAIMER in view.provenance and len(view.provenance) <= 8 * 1024
    assert view.technical == ()
    technical = build_view(older, newer, delta, technical=True).technical
    assert any('Rich product' in line for line in technical)


def test_hostile_values_stay_plain_in_the_view(tmp_path):
    hostile = detects(('compiler', 'Evil‮<img src=x>\x1b[31m', '1.0'))
    older = fingerprint_of(tmp_path, build_with_facts(BuildSpec()), 'older', hostile)
    newer = fingerprint_of(tmp_path, build_with_facts(BuildSpec()), 'newer', detects(('compiler', 'GCC', '10')))
    view = build_view(older, newer, compute_delta(older, newer))
    text = ' '.join([view.state_text, *(r.older + r.newer for r in view.rows), *(b.text for b in view.banners)])
    assert '‮' not in text and '\x1b' not in text and '<img src=x>' in text


def test_banned_strings_never_appear(tmp_path, swap):
    older, newer, delta = swap
    texts = list(copy.deck_texts())
    for fixture in (build_view(older, newer, delta, technical=True),):
        texts += [fixture.state_text, fixture.provenance, *(b.text for b in fixture.banners)]
    lowered = ' '.join(texts).lower().replace('not a vulnerability assessment', '')
    assert [word for word in BANNED if word in lowered] == []
    assert all(text.isascii() for text in copy.deck_texts())


def test_every_warning_code_and_teach_hook_has_copy():
    assert set(copy.TEACH) == {'build.toolchain_differs', 'build.packed', 'build.managed', 'build.installer',
                               'build.unknown', 'build.tool_missing'}
    assert all(1 <= len(h.next_steps) <= 4 for h in copy.TEACH.values())
    assert set(copy.FACT_LABELS) == set(typing.get_args(FactKey)) and len(copy.FACT_LABELS) == 26


# --- anchors and adapters ------------------------------------------------------------------------------------

def test_anchors_are_stable_distinct_and_skip_card_only_facts(swap):
    older, _, _ = swap
    anchors = anchors_for(older)
    assert anchors == anchors_for(older) and len({a.anchor_id for a in anchors}) == len(anchors)
    assert {a.key for a in anchors} <= ANCHOR_KEYS and 'linker_field' not in {a.key for a in anchors}
    assert all(a.side == 'older' and a.artifact_sha256 == older.artifact_sha256 for a in anchors)


def test_entry_id_follows_the_inputs(tmp_path):
    plain = fingerprint_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH)), 'older')
    assert plain.entry_id() == fingerprint_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH)), 'older').entry_id()
    with_die = fingerprint_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH)), 'older', detects(('compiler', 'A', '1')))
    other_db = fingerprint_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH)), 'older',
                              detects(('compiler', 'A', '1')), version='3.20')
    assert len({plain.entry_id(), with_die.entry_id(), other_db.entry_id()}) == 3


def test_adapters_mirror_the_stdlib_facts_and_the_stored_run(tmp_path):
    fp = fingerprint_of(tmp_path, build_with_facts(BuildSpec(rich=MSVC_RICH, debug_types=(2, 16))), 'older')
    assert fp.pe.rich.checksum_ok is True and fp.pe.debug_entry_types == (2, 16) and fp.pe.repro
    manifest = ToolManifest(engine='diec', license='MIT', supported=True, version='3.21', executable_sha256='e' * 64,
                            rules_sha256=LINUX_DB, rules_source='directory')
    run = ToolRun(run_id='r1', engine='diec', side='older', input_artifact_hash='a' * 64, config_digest='b' * 64,
                  cache_key='c' * 64, started_at='2026-10-14T00:00:00Z', elapsed=5, status='ok', profile='full',
                  options={'argv': 'diec/1', 'mode': 'signature'}, manifest=manifest)
    summary = die_summary_from(run)
    assert (summary.tool_version, summary.db_label, summary.argv_version, summary.cache_key) == (
        '3.21', '3.21 linux deb', 'diec/1', 'c' * 64) and not summary.heuristics
    failed = die_summary_from(run.model_copy(update={'status': 'failed'}))
    assert failed.cache_key is None and not failed.produced()
    assert die_summary_from(None) is None
