"""PIL-A3 code-side adapters (docs/specs/program-e/PIL-integration-plan.md s7, s9): Ghidriff and secondary-engine rows,
B1 signals, unified rows and ChangeFacts, T tool deltas, the PE import delta and Ghidriff call labels, all as pilot
observations behind the ports. Synthetic data only (built in code); nothing here is live evidence.

Mandatory gates of PIL-A3: `test_cosmetic_proof_becomes_conflict`, `test_capa_unlocalized_never_attaches`,
`test_floss_static_string_never_attributed`, `test_label_only_calls_cap_verification`.
"""
from __future__ import annotations

import ast
import dataclasses
import hashlib
import os
import random
import subprocess
import sys
import threading
import unicodedata
from pathlib import Path
from typing import get_args

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pe_builder import PeSpec, build_pe
from unified_s0_fixtures import (
    BASE,
    NEW_SHA,
    OLD_SHA,
    SIZE,
    addr_map,
    bd,
    bindiff_set,
    make_project,
    rz,
    rzdiff_set,
)

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.enrichment import signals
from patchtrace.enrichment.contracts import SignalSet
from patchtrace.enrichment.views import build_views, match_view
from patchtrace.intelligence.tools import delta as tool_delta
from patchtrace.intelligence.tools.common import (
    LICENSES,
    CapabilityEvidence,
    EvidenceLink,
    StringEvidence,
    ToolEvidenceSet,
    ToolManifest,
    ToolRun,
)
from patchtrace.intelligence.tools.delta import QualityFlag
from patchtrace.intelligence.tools.normalize import FunctionPairing
from patchtrace.models import FunctionMatch, FunctionRecord
from patchtrace.pe_overview import inspect_pe
from patchtrace.pe_overview.models import DataDirectory, ImportDll, ImportsInfo, PeOverview
from patchtrace.pilot import keys
from patchtrace.pilot.contracts import (
    MAX_SIDE_FUNCTIONS,
    Candidate,
    ChannelStatus,
    FunctionRef,
    Identity,
    Nav,
    Observation,
    ObsRef,
    ToolKey,
)
from patchtrace.pilot.keys import make_observation
from patchtrace.pilot.limits import DEFAULT_LIMITS, Budget, BudgetExhausted, PilotError
from patchtrace.pilot.ports import (
    CallDeltaSource,
    ChangeEvidenceSource,
    PairingSource,
    ToolEvidenceSource,
)
from patchtrace.pilot.sources import pe
from patchtrace.pilot.sources.calls import GhidriffCalls
from patchtrace.pilot.sources.code import (
    IDENTITY_OF_VERDICT,
    MAX_PER_CANDIDATE,
    TEXT_ONLY_REASON,
    B1Evidence,
    CandidateIndex,
    CodeEvidence,
    GhidriffPairing,
    GhidriffRows,
)
from patchtrace.pilot.sources.tools import MAX_PAIR_OBSERVATIONS, ToolDeltas, ToolInput
from patchtrace.pilot.sources.unified import (
    EVIDENCE_CLASS_OF_CHANNEL,
    EVIDENCE_CLASS_OF_PROOF,
    FLAG_TEXT,
    IDENTITY_OF_DECISION,
    NUISANCE_CLASSES,
    NUISANCE_FLAGS,
    QUALITY_FLAGS,
    SHAPE_CLASSES,
    UnifiedFacts,
    UnifiedPairing,
    UnifiedView,
)
from patchtrace.secondary.binexport_identity import PeLayout
from patchtrace.secondary.evidence import Verdict
from patchtrace.secondary.evidence_view import BANNED
from patchtrace.unified import keys as unified_keys
from patchtrace.unified import pipeline, store
from patchtrace.unified.addressing import AddressMap
from patchtrace.unified.contracts import CHANNELS as UNI_CHANNELS
from patchtrace.unified.contracts import (
    Atom,
    ChangeClass,
    ChangeFacts,
    Contest,
    Decision,
    Delta,
    IrRef,
    ProofId,
    RowFlag,
    SideRef,
    SourceRef,
    UnifiedMatch,
)
from patchtrace.unified.pipeline import UnifiedOptions
from patchtrace.unified.store import LoadedResult

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'src' / 'patchtrace' / 'pilot' / 'sources'
RVA_NEWER = 0x1080


def overview(imports: dict[str, list[str]] | None = None, *, base: int | None = BASE, size: int | None = SIZE,
             truncated: bool = False, directory: bool = True) -> PeOverview:
    """A hand-built PE overview: `imports` None = the table could not be read (directory present) or is absent."""
    dirs = (DataDirectory(index=1, name='Import', rva=0x1000 if directory else 0, size=40 if directory else 0,
                          present=directory),)
    info = None if imports is None else ImportsInfo(
        dlls=tuple(ImportDll(name, tuple(names), len(names), truncated) for name, names in imports.items()),
        total_dlls=len(imports), total_functions=sum(len(v) for v in imports.values()), truncated=truncated)
    return PeOverview(size=1, sha256='0' * 64, status='ok', image_base=base, size_of_image=size,
                      data_directories=dirs, imports=info)


# --- pe: layouts and the import delta ------------------------------------------------------------------------------

def test_address_map_turns_virtual_addresses_into_rvas():
    addr = pe.address_map(overview(), overview(base=BASE + 0x10000))
    assert addr is not None
    assert addr.to_rva('older', BASE + 0x1000, 'va') == 0x1000
    assert addr.to_rva('newer', BASE + 0x10000 + 0x1080, 'va') == RVA_NEWER  # each side keeps its own image base


@pytest.mark.parametrize('older,newer', [(overview(base=None), overview()), (overview(), overview(size=None)),
                                         (overview(), overview(size=0))],
                         ids=['no-base', 'no-size', 'zero-size'])
def test_address_map_needs_both_layouts(older, newer):
    assert pe.address_map(older, newer) is None


def test_import_delta_lists_what_the_newer_file_gained_and_lost():
    delta = pe.import_delta(overview({'ntoskrnl.exe': ['RtlCopyMemory', 'ExFreePool']}),
                            overview({'NTOSKRNL.EXE': ['RtlCopyMemory', 'RtlSizeTAdd']}))
    assert delta.state == 'available' and delta.reason is None
    assert delta.added == frozenset({'ntoskrnl.exe!RtlSizeTAdd'})
    assert delta.removed == frozenset({'ntoskrnl.exe!ExFreePool'})  # DLL names compare lower-cased


def test_import_delta_of_equal_tables_is_empty():
    same = {'ntoskrnl.exe': ['A', 'B'], 'hal.dll': ['C']}
    delta = pe.import_delta(overview(same), overview(dict(reversed(same.items()))))
    assert delta.state == 'available' and not delta.added and not delta.removed


def test_import_delta_a_truncated_side_cannot_prove_absence():
    older = overview({'ntoskrnl.exe': ['A']}, truncated=True)
    newer = overview({'ntoskrnl.exe': ['A', 'B']})
    delta = pe.import_delta(older, newer)
    assert delta.state == 'partial' and 'older' in delta.reason
    assert not delta.added  # the older table was cut: B may have been imported before
    delta = pe.import_delta(newer, overview({'ntoskrnl.exe': ['A']}, truncated=True))
    assert delta.state == 'partial' and 'newer' in delta.reason
    assert not delta.removed  # the newer table was cut: B may still be imported


def test_import_delta_an_unreadable_table_is_unknown_not_empty():
    delta = pe.import_delta(overview(None), overview({'ntoskrnl.exe': ['A']}))
    assert delta.state == 'unavailable' and 'older' in delta.reason
    assert not delta.added and not delta.removed and delta.qualify('newer', 'A') is None


def test_import_delta_without_an_import_directory_is_a_valid_empty_table():
    delta = pe.import_delta(overview(None, directory=False), overview({'ntoskrnl.exe': ['A']}))
    assert delta.state == 'available' and delta.added == frozenset({'ntoskrnl.exe!A'})


def test_import_delta_skips_unreadable_names_and_keeps_ordinals():
    delta = pe.import_delta(overview({'a.dll': []}), overview({'a.dll': ['<unreadable @ 0x40>', '#7', 'Real']}))
    assert delta.added == frozenset({'a.dll!#7', 'a.dll!Real'}) and delta.state == 'partial'


def test_qualify_names_the_dll_only_when_exactly_one_imports_the_name():
    delta = pe.import_delta(overview({}), overview({'ntoskrnl.exe': ['RtlSizeTAdd', 'Shared'],
                                                    'hal.dll': ['Shared']}))
    assert delta.qualify('newer', 'RtlSizeTAdd') == 'ntoskrnl.exe!RtlSizeTAdd'
    assert delta.qualify('newer', 'Shared') is None  # two DLLs: ambiguous, never a guess
    assert delta.qualify('newer', 'rtlsizetadd') is None and delta.qualify('older', 'RtlSizeTAdd') is None


def test_the_real_parser_feeds_the_import_delta(tmp_path):
    def parse(name: str, imports: dict) -> PeOverview:
        path = tmp_path / name
        path.write_bytes(build_pe(PeSpec(imports=imports)))
        with VerifiedArtifactReader.open_path(path) as reader:
            return inspect_pe(reader)
    older = parse('old.bin', {'ntoskrnl.exe': ['RtlCopyMemory']})
    newer = parse('new.bin', {'ntoskrnl.exe': ['RtlCopyMemory', 'RtlSizeTAdd'], 'hal.dll': ['HalFoo']})
    delta = pe.import_delta(older, newer)
    assert delta.state == 'available'
    assert delta.added == frozenset({'ntoskrnl.exe!RtlSizeTAdd', 'hal.dll!HalFoo'}) and not delta.removed
    addr = pe.address_map(older, newer)
    assert addr is not None and addr.older.image_base == 0x140000000


# --- Ghidriff rows, the candidate universe and secondary-engine identity ------------------------------------------------

RUN = 'run-1'
GUARD_OLD = 'int read_item(char *b, int n, int i) {\n  return b[i];\n}'
GUARD_NEW = ('int read_item(char *b, int n, int i) {\n  if (i >= n) {\n    return -1;\n  }\n'
             '  return b[i];\n}')


def va(rva: int) -> str:
    return f'{BASE + rva:x}'


def rec(side: str, name: str, rva: int | None, *, code: str | None = None, callees=(), space: str = 'virtual',
        fid: str | None = None, base: int = BASE) -> FunctionRecord:
    return FunctionRecord(id=fid or f'{side}-{name}', artifact_id=f'art-{side}', run_id=RUN, name=name,
                          address=None if rva is None else f'{base + rva:x}', address_space=space, code=code,
                          callees=list(callees))


def fmatch(mid: str, category: str, older=(), newer=(), *, manual: bool = False, run_id: str = RUN) -> FunctionMatch:
    return FunctionMatch(id=mid, run_id=run_id, category=category, older=list(older), newer=list(newer),
                         manual=manual)


def read_item(callees_new=()) -> FunctionMatch:
    return fmatch('m-read', 'modified', [rec('older', 'read_item', 0x1000, code=GUARD_OLD)],
                  [rec('newer', 'read_item', RVA_NEWER, code=GUARD_NEW, callees=callees_new)])


def get_version() -> FunctionMatch:
    return fmatch('m-ver', 'modified', [rec('older', 'get_version', 0x1600, code='int get_version(void) { return 1; }')],
                  [rec('newer', 'get_version', 0x1700, code='int get_version(void) { return 2; }')])


def added_fn() -> FunctionMatch:
    return fmatch('m-add', 'added', newer=[rec('newer', 'report_invalid_index', 0x1800)])


def removed_fn() -> FunctionMatch:
    return fmatch('m-del', 'removed', older=[rec('older', 'debug_dump', 0x1400, callees=['puts'])])


def scenario() -> list[FunctionMatch]:
    return [read_item(['report_invalid_index']), get_version(), added_fn(), removed_fn()]


def key_of(older=(), newer=()) -> str:
    return keys.candidate_key(OLD_SHA, NEW_SHA, list(older), list(newer))


def resolve(matches=None, **kw) -> GhidriffRows:
    return GhidriffRows.resolve(OLD_SHA, NEW_SHA, scenario() if matches is None else matches, addr_map(), **kw)


def test_rows_resolve_to_rvas_and_the_unified_row_id():
    rows = resolve()
    assert [r.match.id for r in rows.rows] == sorted(r.match.id for r in rows.rows) and len(rows.rows) == 4
    by_id = {r.match.id: r for r in rows.rows}
    assert by_id['m-read'].candidate_key == key_of([0x1000], [RVA_NEWER])
    assert by_id['m-read'].candidate_key == unified_keys.row_id(OLD_SHA, NEW_SHA, [0x1000], [RVA_NEWER])  # parity
    assert by_id['m-add'].candidate_key == key_of(newer=[0x1800]) and by_id['m-add'].older == ()
    assert by_id['m-del'].candidate_key == key_of(older=[0x1400]) and by_id['m-del'].newer == ()
    assert rows.state == 'available' and rows.unresolved == 0 and rows.run_id == RUN


def test_rows_accept_addresses_that_already_are_rvas():
    older = fmatch('m1', 'modified', [rec('older', 'f', 0x1000, base=0)], [rec('newer', 'f', 0x1080, base=0)])
    rows = resolve([older])
    assert rows.rows[0].candidate_key == key_of([0x1000], [0x1080])


def test_rows_with_mixed_address_bases_resolve_nothing():
    older = fmatch('m1', 'modified', [rec('older', 'f', 0x1000)], [rec('newer', 'f', 0x1080, base=0)])
    rows = resolve([older])
    assert rows.rows == () and rows.state == 'unsupported' and 'address' in rows.reason


def test_rows_without_an_address_or_in_file_offset_space_are_counted_and_left_out():
    nameless = fmatch('m2', 'removed', older=[rec('older', 'noaddr', None)])
    offset = fmatch('m3', 'added', newer=[rec('newer', 'off', 0x1100, space='file-offset')])
    rows = resolve([read_item(), nameless, offset])
    assert [r.match.id for r in rows.rows] == ['m-read'] and rows.unresolved == 2 and rows.state == 'available'


def test_rows_with_an_address_outside_the_image_make_the_set_not_comparable():
    """The basis rule of the unified engine (06 s1): one stray address would silently re-base the others."""
    outside = fmatch('m1', 'added', newer=[rec('newer', 'far', SIZE + 0x100)])
    rows = resolve([read_item(), outside])
    assert rows.rows == () and rows.state == 'unsupported' and 'address' in rows.reason


def test_rows_without_a_pe_layout_are_unsupported():
    rows = GhidriffRows.resolve(OLD_SHA, NEW_SHA, scenario(), None)
    assert rows.rows == () and rows.state == 'unsupported' and 'layout' in rows.reason


def test_rows_of_two_runs_are_refused():
    with pytest.raises(PilotError) as info:
        resolve([read_item(), fmatch('m2', 'added', newer=[rec('newer', 'x', 0x1100)], run_id='run-2')])
    assert (info.value.code, info.value.reason) == ('PT-PILOT-INPUT', 'mixed-runs')


def test_rows_with_the_same_endpoints_are_one_candidate():
    twin = fmatch('m-twin', 'modified', [rec('older', 'read_item', 0x1000, fid='o2')],
                  [rec('newer', 'read_item', RVA_NEWER, fid='n2')], manual=True)
    rows = resolve([read_item(), twin])
    assert len(rows.rows) == 1 and rows.by_match['m-read'] is rows.by_match['m-twin']


def test_rows_group_matches_keep_every_function():
    group = fmatch('m-split', 'split', [rec('older', 'big', 0x1000)],
                   [rec('newer', 'part_b', 0x1100), rec('newer', 'part_a', 0x1040)])
    row = resolve([group]).rows[0]
    assert [rva for rva, _ in row.newer] == [0x1040, 0x1100] and row.candidate_key == key_of([0x1000], [0x1040, 0x1100])


def test_rows_over_the_candidate_limit_fail_loudly():
    limits = dataclasses.replace(DEFAULT_LIMITS, p01_candidates=3)
    with pytest.raises(PilotError) as info:
        resolve(limits=limits)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-LIMIT', 'candidates')


def test_rows_stop_when_cancelled():
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(BudgetExhausted) as info:
        resolve(budget=Budget(None, cancel, check_every=1))
    assert info.value.code == 'PT-PILOT-CANCEL'


def test_rows_do_not_depend_on_input_order():
    base = resolve()
    for seed in range(5):
        shuffled = scenario()
        random.Random(seed).shuffle(shuffled)
        assert [r.candidate_key for r in resolve(shuffled).rows] == [r.candidate_key for r in base.rows]


def wide_map():
    layout = PeLayout(image_base=BASE, size_of_image=0x4000)
    return AddressMap(layout, layout)


def bindiff_for(*pairs: tuple[int, int], older: str = OLD_SHA, newer: str = NEW_SHA):
    return bindiff_set([bd(o, n) for o, n in pairs], older=older, newer=newer)


def candidates_of(pairing) -> dict[str, Candidate]:
    return {c.candidate_key: c for c in pairing.candidates()}


def test_pairing_lists_every_row_once_with_names_and_no_verdict_without_engines():
    pairing = GhidriffPairing(resolve())
    found = list(pairing.candidates())
    assert [c.candidate_key for c in found] == sorted(c.candidate_key for c in found) and len(found) == 4
    read = candidates_of(pairing)[key_of([0x1000], [RVA_NEWER])]
    assert (read.older[0].rva, read.older[0].name, read.newer[0].rva) == (0x1000, 'read_item', RVA_NEWER)
    assert {c.identity for c in found} == {'unassessed'}
    assert pairing.unified_result_id() is None and pairing.secondary_set_ids() == ()
    status = pairing.status()
    assert (status.channel, status.state) == ('pairing', 'partial') and 'unassessed' in status.reason


def test_pairing_identity_follows_the_secondary_engine_verdicts():
    sets = [bindiff_for((0x1000, RVA_NEWER), (0x1600, 0x1780))]  # agrees on read_item, pairs get_version elsewhere
    pairing = GhidriffPairing(resolve(), sets)
    found = candidates_of(pairing)
    assert found[key_of([0x1000], [RVA_NEWER])].identity == 'corroborated'
    assert found[key_of([0x1600], [0x1700])].identity == 'contested'
    assert found[key_of(newer=[0x1800])].identity == 'unassessed'  # absent from the engine: single engine, no vote
    assert pairing.status().state == 'available'
    assert pairing.secondary_set_ids() == (sets[0].entry_id,)


@pytest.mark.parametrize('verdict,identity', [('corroborated', 'corroborated'), ('contested', 'contested'),
                                              ('single-engine', 'unassessed'), ('insufficient', 'unassessed')],
                         ids=['corroborated', 'contested', 'single-engine', 'insufficient'])
def test_every_secondary_verdict_maps_to_an_identity(verdict, identity):
    assert IDENTITY_OF_VERDICT[verdict] == identity
    assert set(IDENTITY_OF_VERDICT) == set(get_args(Verdict))  # a new verdict must be placed on purpose


def test_pairing_ignores_secondary_sets_of_another_pair_and_says_so():
    other = bindiff_for((0x1000, RVA_NEWER), older='c' * 64, newer='d' * 64)
    reversed_pair = bindiff_for((RVA_NEWER, 0x1000), older=NEW_SHA, newer=OLD_SHA)
    pairing = GhidriffPairing(resolve(), [other, reversed_pair])
    assert {c.identity for c in pairing.candidates()} == {'unassessed'} and pairing.secondary_set_ids() == ()
    status = pairing.status()
    assert status.state == 'partial' and 'reversed' in status.reason and 'another pair' in status.reason


def test_pairing_two_sets_of_one_engine_are_refused():
    first, second = bindiff_for((0x1000, RVA_NEWER)), bindiff_set([bd(0x1600, 0x1700)], file_sha='9' * 64)
    with pytest.raises(PilotError) as info:
        GhidriffPairing(resolve(), [first, second])
    assert (info.value.code, info.value.reason) == ('PT-PILOT-INPUT', 'secondary-sets')


@pytest.mark.parametrize('rows,state', [
    (GhidriffRows.resolve(OLD_SHA, NEW_SHA, [], addr_map()), 'not-run'),
    (GhidriffRows.resolve(OLD_SHA, NEW_SHA, scenario(), None), 'unsupported'),
], ids=['no-run', 'no-layout'])
def test_pairing_without_usable_rows_reports_why(rows, state):
    pairing = GhidriffPairing(rows)
    assert list(pairing.candidates()) == [] and pairing.status().state == state and pairing.status().reason


def test_pairing_with_unresolved_rows_is_partial_even_with_engines():
    nameless = fmatch('m1', 'removed', older=[rec('older', 'noaddr', None)])
    pairing = GhidriffPairing(resolve([read_item(), nameless]), [bindiff_for((0x1000, RVA_NEWER))])
    status = pairing.status()
    assert status.state == 'partial' and '1 row' in status.reason


def test_candidate_index_finds_every_candidate_holding_a_function():
    group = fmatch('m-split', 'split', [rec('older', 'big', 0x1000)], [rec('newer', 'part_a', 0x1040)])
    pairing = GhidriffPairing(resolve([read_item(), group]))
    index = CandidateIndex(pairing.candidates())
    assert set(index.keys_at('older', 0x1000)) == {key_of([0x1000], [RVA_NEWER]), key_of([0x1000], [0x1040])}
    assert index.keys_at('newer', 0x1040) == (key_of([0x1000], [0x1040]),) and index.keys_at('newer', 0x9999) == ()


# --- B1 signals ------------------------------------------------------------------------------------------------------

READ_KEY = key_of([0x1000], [RVA_NEWER])
VER_KEY = key_of([0x1600], [0x1700])


def signal_sets(matches=None) -> list[SignalSet]:
    """The real B1 detectors over the synthetic functions (lexical heuristics on decompiler text, as in production)."""
    return [signals.detect(match_view(m, '0' * 64, {'older': 'art-older', 'newer': 'art-newer'}))
            for m in (scenario() if matches is None else matches)]


def b1(rows=None, sets=None, **kw) -> B1Evidence:
    return B1Evidence(rows or resolve(), signal_sets() if sets is None else sets, **kw)


def grouped(source, wanted) -> dict[str, list[Observation]]:
    found: dict[str, list[Observation]] = {}
    for key, observation in source.observations(wanted):
        found.setdefault(key, []).append(observation)
    return found


def read_signal(detector: str):
    sets = {s.match_id: s for s in signal_sets()}
    return next(s for s in sets['m-read'].signals if s.detector == detector)


def test_b1_signals_become_shape_observations_on_the_newer_function():
    found = {o.kind: o for o in grouped(b1(), [READ_KEY])[READ_KEY]}
    assert set(found) == {'b1:BND', 'b1:ERR'}
    bnd, signal = found['b1:BND'], read_signal('BND')
    assert (bnd.channel, bnd.role, bnd.verification, bnd.origins, bnd.evidence_class) == (
        'code', 'shape', 'tool-reported', ('D_ghidra',), 'E-DECOMP')
    location = signal.locations[0]
    assert bnd.ref == ObsRef(kind='b1-signal', id=signal.signal_id)
    assert bnd.nav == Nav(side='newer', rva=RVA_NEWER, start_line=location.start_line, end_line=location.end_line)
    assert bnd.detail == signal.rationale and keys.observation_id(bnd) == bnd.obs_id


def test_b1_gives_observations_only_for_the_requested_candidates():
    source = b1()
    assert list(source.observations([])) == [] and list(source.observations([VER_KEY, 'f' * 64])) == []
    assert set(grouped(source, [READ_KEY, VER_KEY])) == {READ_KEY}  # a pair without a signal yields nothing, not a no


def test_b1_status_is_available_when_every_pair_was_covered():
    assert b1().status() == ChannelStatus(channel='code', state='available')


def test_b1_status_not_run_without_signal_sets_or_rows():
    assert b1(sets=[]).status().state == 'not-run'
    empty = GhidriffRows.resolve(OLD_SHA, NEW_SHA, [], addr_map())
    assert B1Evidence(empty, signal_sets()).status().state == 'not-run'


def test_b1_status_a_pair_without_a_signal_set_is_unknown_coverage():
    sets = [s for s in signal_sets() if s.match_id != 'm-ver']
    status = b1(sets=sets).status()
    assert status.state == 'partial' and '1 of 2' in status.reason


def test_b1_status_missing_decompiled_code_is_partial_never_a_clean_no():
    nocode = fmatch('m-nocode', 'modified', [rec('older', 'nc', 0x1200)], [rec('newer', 'nc', 0x1280)])
    matches = [read_item(), nocode]
    source = B1Evidence(resolve(matches), signal_sets(matches))
    assert source.status().state == 'partial' and '1 of 2' in source.status().reason


def test_b1_status_signal_sets_of_another_run_are_stale():
    foreign = signal_sets([fmatch('x1', 'modified', [rec('older', 'a', 0x1700, code=GUARD_OLD)],
                                  [rec('newer', 'a', 0x1740, code=GUARD_NEW)])])
    assert b1(sets=foreign).status().state == 'stale'
    mixed = b1(sets=[*signal_sets(), *foreign]).status()
    assert mixed.state == 'partial' and '1 signal set' in mixed.reason


def test_b1_two_signal_sets_for_one_match_are_refused():
    sets = signal_sets()
    with pytest.raises(PilotError) as info:
        b1(sets=[*sets, sets[0]])
    assert (info.value.code, info.value.reason) == ('PT-PILOT-INPUT', 'duplicate-signal-set')


def test_b1_caps_the_signals_of_one_candidate_and_says_so():
    sets = signal_sets()
    template = read_signal('BND')
    many = tuple(template.model_copy(update={'signal_id': f'{i:064x}', 'group_key': f'{i:064x}'})
                 for i in range(MAX_PER_CANDIDATE + 6))
    sets = [s.model_copy(update={'signals': many}) if s.match_id == 'm-read' else s for s in sets]
    source = b1(sets=sets)
    assert len(grouped(source, [READ_KEY])[READ_KEY]) == MAX_PER_CANDIDATE
    assert source.status().state == 'partial' and 'cap' in source.status().reason


def test_b1_rationale_text_is_plain_and_bounded():
    hostile = read_signal('BND').model_copy(update={'rationale': 'new check <b>x</b>\n\u202eevil ' + 'y' * 500})
    sets = [s.model_copy(update={'signals': (hostile,)}) if s.match_id == 'm-read' else s for s in signal_sets()]
    detail = grouped(b1(sets=sets), [READ_KEY])[READ_KEY][0].detail
    assert len(detail) == 300 and detail.endswith('...') and '\n' not in detail and '\u202e' not in detail
    assert '<b>x</b>' in detail  # markup is kept as inert text, never interpreted


def test_b1_output_does_not_depend_on_input_order():
    expected = [(k, o.obs_id) for k, o in b1().observations([READ_KEY, VER_KEY])]
    assert expected
    for seed in range(5):
        sets = signal_sets()
        random.Random(seed).shuffle(sets)
        matches = scenario()
        random.Random(seed).shuffle(matches)
        shuffled = B1Evidence(resolve(matches), sets)
        assert [(k, o.obs_id) for k, o in shuffled.observations([VER_KEY, READ_KEY])] == expected


# --- the code channel: B1 plus optional typed facts ----------------------------------------------------------------


class Canned:
    """A stand-in `ChangeEvidenceSource`: fixed status and observations."""

    def __init__(self, state: str, reason: str | None = None, items=()):
        self._status, self._items = ChannelStatus(channel='code', state=state, reason=reason), tuple(items)

    def status(self):
        return self._status

    def observations(self, candidate_keys):
        wanted = set(candidate_keys)
        return iter(sorted(((k, o) for k, o in self._items if k in wanted), key=lambda item: (item[0], item[1].obs_id)))


def test_without_typed_facts_the_ceiling_is_text_evidence_only():
    code = CodeEvidence(b1())
    status = code.status()
    assert (status.channel, status.state, status.reason) == ('code', 'partial', TEXT_ONLY_REASON)
    assert list(code.observations([READ_KEY])) == list(b1().observations([READ_KEY]))


@pytest.mark.parametrize('lexical,typed,state', [
    ('available', 'available', 'available'), ('available', 'partial', 'partial'), ('partial', 'available', 'partial'),
    ('not-run', 'available', 'partial'), ('available', 'not-run', 'partial'), ('available', 'failed', 'partial'),
    ('not-run', 'not-run', 'not-run'), ('stale', 'unsupported', 'unsupported'), ('failed', 'not-run', 'failed'),
], ids=['both', 'typed-partial', 'lexical-partial', 'no-b1', 'no-typed', 'typed-failed', 'neither', 'stale-unsupported',
        'failed'])
def test_the_code_channel_state_follows_what_either_source_could_see(lexical, typed, state):
    status = CodeEvidence(Canned(lexical, 'b1 note'), Canned(typed, 'typed note')).status()
    assert status.state == state and (status.reason is None) == (state == 'available')


def test_the_code_channel_with_one_source_that_saw_nothing_says_why():
    status = CodeEvidence(Canned('not-run', 'B1 has not run')).status()
    assert (status.state, status.reason) == ('not-run', 'B1 has not run')


def test_the_code_channel_merges_both_sources_in_one_deterministic_order():
    lexical = b1()
    typed = Canned('available', items=[(READ_KEY, make_observation(
        channel='code', kind='cf:comparison', role='shape', verification='tool-reported', origins=('D_ghidra',),
        evidence_class='E-BODY', ref=ObsRef(kind='change-facts', id=READ_KEY), detail='new comparison'))])
    merged = list(CodeEvidence(lexical, typed).observations([VER_KEY, READ_KEY]))
    assert {o.kind for _, o in merged} == {'b1:BND', 'b1:ERR', 'cf:comparison'}
    assert merged == sorted(merged, key=lambda item: (item[0], item[1].obs_id))


# --- Ghidriff call labels and the PE import delta -----------------------------------------------------------------------

CALL_OLD, CALL_NEW = 0x1200, 0x1280
CALL_KEY = key_of([CALL_OLD], [CALL_NEW])


def call_match(old_calls=(), new_calls=(), mid: str = 'm-call') -> FunctionMatch:
    return fmatch(mid, 'modified', [rec('older', 'f', CALL_OLD, callees=old_calls)],
                  [rec('newer', 'f', CALL_NEW, callees=new_calls)])


def calls_of(matches, imports=None, **kw) -> GhidriffCalls:
    return GhidriffCalls(resolve(matches), imports, **kw)


def call_obs(source, wanted=(CALL_KEY,)) -> list[Observation]:
    return [o for _, o in source.observations(wanted)]


def imports_delta(older: dict, newer: dict):
    return pe.import_delta(overview(older), overview(newer))


@pytest.mark.parametrize('imports', [
    None,
    pe.import_delta(overview(None), overview({'ntoskrnl.exe': ['RtlSizeTAdd']})),
    imports_delta({'ntoskrnl.exe': ['RtlCopyMemory']}, {'ntoskrnl.exe': ['RtlCopyMemory', 'RtlSizeTAdd']}),
], ids=['no-imports', 'unreadable-imports', 'import-gained'])
def test_label_only_calls_cap_verification(imports):
    """A callee name from Ghidriff is a label: never verified bytes, never a tool report, whatever else is known."""
    found = call_obs(calls_of([call_match([], ['RtlSizeTAdd'])], imports))
    labels = [o for o in found if o.origins == ('D_ghidra',)]
    assert [o.kind for o in labels] == ['call:added']
    assert labels[0].verification == 'label-only' and labels[0].role == 'shape' and labels[0].channel == 'calls'
    assert labels[0].evidence_class == 'E-CALL' and labels[0].ref == ObsRef(kind='call-label', id='RtlSizeTAdd')
    assert labels[0].anchor_ids == ('api:RtlSizeTAdd',) and labels[0].nav == Nav(side='newer', rva=CALL_NEW)
    assert labels[0].detail == 'call to RtlSizeTAdd added (label only)'
    assert all(o.verification in ('label-only', 'verified-bytes') for o in found)
    assert not [o for o in found if o.verification == 'verified-bytes' and o.origins != ('D_pe_tables',)]


def test_removed_calls_sit_on_the_older_function():
    found = call_obs(calls_of([call_match(['puts', 'kept'], ['kept'])]))
    assert [(o.kind, o.nav) for o in found] == [('call:removed', Nav(side='older', rva=CALL_OLD))]
    assert found[0].detail == 'call to puts removed (label only)'


def test_equal_callee_sets_yield_nothing_whatever_the_order_or_multiplicity():
    assert call_obs(calls_of([call_match(['a', 'b', 'b'], ['b', 'a'])])) == []


@pytest.mark.parametrize('label', ['FUN_180001234', 'thunk_FUN_180001234', 'sub_401000', 'FUN_1400'],
                         ids=['fun', 'thunk-fun', 'ida-sub', 'short'])
def test_default_decompiler_labels_are_not_api_names(label):
    """FUN_<address> differs in every build: an added or removed one is renumbering, not a call change."""
    assert call_obs(calls_of([call_match([label], [])])) == []


def test_a_gained_import_is_a_second_witness_from_the_pe_tables():
    imports = imports_delta({'ntoskrnl.exe': ['RtlCopyMemory']}, {'ntoskrnl.exe': ['RtlCopyMemory', 'RtlSizeTAdd']})
    found = call_obs(calls_of([call_match([], ['RtlSizeTAdd'])], imports))
    assert sorted(o.origins for o in found) == [('D_ghidra',), ('D_pe_tables',)]  # two components, not one
    table = next(o for o in found if o.origins == ('D_pe_tables',))
    assert (table.kind, table.role, table.verification, table.channel) == ('call:added', 'shape', 'verified-bytes', 'calls')
    assert table.ref == ObsRef(kind='pe-import', id='ntoskrnl.exe!RtlSizeTAdd') and table.nav is None
    assert table.anchor_ids == ('api:ntoskrnl.exe!RtlSizeTAdd',) and table.detail == (
        'module import table gained ntoskrnl.exe!RtlSizeTAdd')


def test_a_dropped_import_corroborates_a_removed_call():
    imports = imports_delta({'ntoskrnl.exe': ['ExFreePool', 'Keep']}, {'ntoskrnl.exe': ['Keep']})
    found = call_obs(calls_of([call_match(['ExFreePool'], [])], imports))
    table = next(o for o in found if o.origins == ('D_pe_tables',))
    assert (table.kind, table.detail) == ('call:removed', 'module import table dropped ntoskrnl.exe!ExFreePool')


@pytest.mark.parametrize('older,newer', [
    ({'ntoskrnl.exe': ['RtlSizeTAdd']}, {'ntoskrnl.exe': ['RtlSizeTAdd']}),  # already imported: no new import
    ({'x.dll': []}, {'ntoskrnl.exe': ['RtlSizeTAdd'], 'hal.dll': ['RtlSizeTAdd']}),  # two DLLs: ambiguous
    ({'x.dll': []}, {'ntoskrnl.exe': ['SomethingElse']}),  # the name is not imported at all
], ids=['already-imported', 'ambiguous', 'not-imported'])
def test_no_pe_witness_without_a_gained_import_that_names_one_dll(older, newer):
    found = call_obs(calls_of([call_match([], ['RtlSizeTAdd'])], imports_delta(older, newer)))
    assert [o.origins for o in found] == [('D_ghidra',)]


def test_the_pe_witness_is_one_pool_entry_for_every_candidate_that_uses_it():
    imports = imports_delta({'x.dll': []}, {'ntoskrnl.exe': ['RtlSizeTAdd']})
    second = fmatch('m-two', 'modified', [rec('older', 'g', 0x1400)], [rec('newer', 'g', 0x1440,
                                                                           callees=['RtlSizeTAdd'])])
    source = calls_of([call_match([], ['RtlSizeTAdd']), second], imports)
    other = key_of([0x1400], [0x1440])
    ids = {k: {o.obs_id for o in call_obs(source, [k]) if o.origins == ('D_pe_tables',)} for k in (CALL_KEY, other)}
    assert ids[CALL_KEY] and ids[CALL_KEY] == ids[other]


def test_calls_are_assessed_for_one_to_one_pairs_only():
    group = fmatch('m-split', 'split', [rec('older', 'big', 0x1500)],
                   [rec('newer', 'a', 0x1540, callees=['x']), rec('newer', 'b', 0x1580)])
    one_sided = fmatch('m-add', 'added', newer=[rec('newer', 'new', 0x1600, callees=['y'])])
    source = calls_of([call_match([], ['z']), group, one_sided])
    assert [k for k, _ in source.observations([key_of([0x1500], [0x1540, 0x1580]), key_of(newer=[0x1600])])] == []
    assert '1 group row' in source.status().reason  # unknown for the group, said out loud


def test_calls_status_is_partial_with_labels_and_says_what_is_missing():
    status = calls_of([call_match([], ['z'])]).status()
    assert (status.channel, status.state) == ('calls', 'partial')
    assert 'labels only' in status.reason and 'no PE import delta' in status.reason
    with_imports = calls_of([call_match([], ['z'])], imports_delta({'x.dll': []}, {'x.dll': []})).status()
    assert 'no PE import delta' not in with_imports.reason
    broken = calls_of([call_match([], ['z'])], pe.import_delta(overview(None), overview({}))).status()
    assert 'import delta' in broken.reason and broken.state == 'partial'


def test_calls_status_without_rows_or_callee_lists():
    assert GhidriffCalls(GhidriffRows.resolve(OLD_SHA, NEW_SHA, [], addr_map())).status().state == 'not-run'
    assert GhidriffCalls(GhidriffRows.resolve(OLD_SHA, NEW_SHA, scenario(), None)).status().state == 'unsupported'
    bare = GhidriffCalls(resolve([call_match(), get_version()])).status()
    assert bare.state == 'unsupported' and 'callee' in bare.reason  # no list at all is unknown, not "no calls"


def test_calls_cap_and_say_so():
    names = [f'Api{i:03d}' for i in range(MAX_PER_CANDIDATE + 5)]
    source = calls_of([call_match([], names)])
    assert len(call_obs(source)) == MAX_PER_CANDIDATE and 'cap' in source.status().reason


def test_call_labels_are_plain_text_and_anchors_only_when_printable():
    long_name = 'L' * 300
    source = calls_of([call_match([], ['bad\u202ename\n', 'café', 'two words', long_name, '\u202e'])])
    found = {o.ref.id: o for o in call_obs(source)}
    assert set(found) - {'café', 'two words'} >= {'badname'}
    assert all('\u202e' not in o.detail and '\n' not in o.detail for o in found.values())
    assert found['café'].anchor_ids == () and found['two words'].anchor_ids == ()  # an anchor id has no spaces or accents
    assert len(found[next(i for i in found if i.startswith('LLL'))].ref.id) <= 256
    assert len(found) == 4  # the label that is nothing but a bidi mark is dropped


def test_calls_do_not_depend_on_input_order():
    names = [f'Api{i}' for i in range(8)]
    base = [(k, o.obs_id) for k, o in calls_of([call_match([], names)]).observations([CALL_KEY])]
    for seed in range(5):
        shuffled = names[:]
        random.Random(seed).shuffle(shuffled)
        again = [(k, o.obs_id) for k, o in calls_of([call_match([], shuffled)]).observations([CALL_KEY])]
        assert again == base


# --- T tool deltas: capa, FLOSS and DiE -------------------------------------------------------------------------------
# Built with T's own contracts and `delta.compute`, so the attachment rules meet T's real classifications.

SHA_OF = {'older': OLD_SHA, 'newer': NEW_SHA}


def tool_manifest(engine: str, backend: str | None = 'vivisect') -> ToolManifest:
    return ToolManifest(engine=engine, version='1.0.0', executable_sha256='e' * 64, license=LICENSES[engine],
                        rules_source='embedded', supported=True, backend=backend if engine == 'capa' else None)


def tool_run(engine: str, side: str, *, status: str = 'ok', backend: str | None = 'vivisect', cache: str = 'c',
             sha: str | None = None) -> ToolRun:
    code = None if status in ('ok', 'none-found') else {'failed': 'PT-TOOL-RUN', 'timeout': 'PT-TOOL-TIMEOUT',
                                                         'unsupported': 'PT-TOOL-UNSUPPORTED'}[status]
    return ToolRun(run_id=f'{engine}-{side}', engine=engine, side=side, input_artifact_hash=sha or SHA_OF[side],
                   config_digest='d' * 64, cache_key=cache * 64, started_at='t', elapsed=0, status=status,
                   error=None if code is None else 'x', error_code=code, profile='full',
                   manifest=tool_manifest(engine, backend))


def link(side: str, rva: int | None = None, attribution: str = 'function-start', *, function: int | None = None,
         engine: str = 'capa') -> EvidenceLink:
    if attribution == 'none':
        return EvidenceLink(tool_run_id=f'{engine}-{side}', artifact_sha256=SHA_OF[side], rva=rva)
    return EvidenceLink(tool_run_id=f'{engine}-{side}', artifact_sha256=SHA_OF[side],
                        function_id=f'rva:0x{rva if function is None else function:x}', rva=rva,
                        attribution=attribution)


def capability(side: str, rule: str, where: EvidenceLink, *, scope: str = 'function', kind: str = 'capability',
               namespace: str = 'data-manipulation/encryption') -> CapabilityEvidence:
    return CapabilityEvidence(rule_id=rule, rule_sha256='f' * 64, namespace=namespace, scope=scope,
                              address_space='relative', address=where.rva, location=where, kind=kind,
                              source_run_id=f'capa-{side}')


def string(side: str, text: str, kind: str, where: EvidenceLink) -> StringEvidence:
    return StringEvidence(value_hash=hashlib.sha256(text.encode()).hexdigest(), length=len(text), display_value=text,
                          encoding='ASCII', type=kind, source_location=where, confidence_class='tool-reported',
                          extraction_method=f'floss-{kind}', source_run_id=f'floss-{side}')


def evidence(engine: str, side: str, **items) -> ToolEvidenceSet:
    return ToolEvidenceSet(run_id=f'{engine}-{side}', engine=engine, side=side, artifact_sha256=SHA_OF[side],
                           cache_key='c' * 64, config_digest='d' * 64, **items)


def project_pairing(matches=None, unchanged=()) -> FunctionPairing:
    table = {va(o): [[va(n), ['ExactBytesFunctionHasher']]] for o, n in unchanged}
    return FunctionPairing.from_project(scenario() if matches is None else matches, {'address_matches': table},
                                        older_base=BASE, newer_base=BASE, older_size=SIZE, newer_size=SIZE)


def tool_input(engine: str, older: ToolEvidenceSet, newer: ToolEvidenceSet, *, pairing=None, flags=(),
               backend: str | None = 'vivisect', show_secrets: bool = False) -> ToolInput:
    old_run, new_run = tool_run(engine, 'older', backend=backend), tool_run(engine, 'newer', backend=backend)
    result = tool_delta.compute(old_run, older, new_run, newer, pairing=pairing or project_pairing(), flags=flags,
                                show_secrets=show_secrets)
    return ToolInput(engine, result, old_run, new_run)


def tools_for(*inputs: ToolInput, candidates=None, **kw) -> ToolDeltas:
    found = candidates if candidates is not None else list(GhidriffPairing(resolve()).candidates())
    return ToolDeltas(inputs, CandidateIndex(found), older_sha256=OLD_SHA, newer_sha256=NEW_SHA, **kw)


def capa_input(older_caps=(), newer_caps=(), **kw) -> ToolInput:
    return tool_input('capa', evidence('capa', 'older', capabilities=tuple(older_caps)),
                      evidence('capa', 'newer', capabilities=tuple(newer_caps)), **kw)


def floss_input(older=(), newer=(), **kw) -> ToolInput:
    return tool_input('floss', evidence('floss', 'older', strings=tuple(older)),
                      evidence('floss', 'newer', strings=tuple(newer)), **kw)


def tool_obs(source, wanted=None) -> list[tuple[str, Observation]]:
    keys_ = [READ_KEY, VER_KEY, key_of(newer=[0x1800]), key_of(older=[0x1400])] if wanted is None else wanted
    return list(source.observations(keys_))


AES = 'encrypt data using AES'


def test_capa_added_in_a_changed_function_attaches_to_that_candidate_as_context():
    source = tools_for(capa_input([], [capability('newer', AES, link('newer', RVA_NEWER))]))
    found = tool_obs(source)
    assert [k for k, _ in found] == [READ_KEY]
    obs = found[0][1]
    assert (obs.kind, obs.role, obs.channel, obs.verification) == ('capa:added', 'context', 'capa', 'tool-reported')
    assert obs.origins == ('D_vivisect',) and obs.evidence_class == 'E-CAPA'
    assert obs.ref == ObsRef(kind='capa-rule', id=AES) and obs.nav == Nav(side='newer', rva=RVA_NEWER)
    assert obs.detail == f'capa matches {AES} in the newer function only'


def test_capa_removed_in_a_changed_function_sits_on_the_older_function():
    source = tools_for(capa_input([capability('older', AES, link('older', 0x1000))], []))
    [(key, obs)] = tool_obs(source)
    assert (key, obs.kind, obs.nav) == (READ_KEY, 'capa:removed', Nav(side='older', rva=0x1000))


def test_capa_basic_block_matches_attach_to_the_owning_function():
    where = link('newer', RVA_NEWER + 0x40, 'basic-block-in-function', function=RVA_NEWER)
    [(key, obs)] = tool_obs(tools_for(capa_input([], [capability('newer', AES, where, scope='basic block')])))
    assert key == READ_KEY and obs.nav == Nav(side='newer', rva=RVA_NEWER)  # the function, not the block address


def test_capa_origin_follows_the_backend():
    caps = [capability('newer', AES, link('newer', RVA_NEWER))]
    ghidra = tools_for(capa_input([], caps, backend='ghidra'))
    assert tool_obs(ghidra)[0][1].origins == ('D_ghidra',)  # capa on Ghidra is not independent of Ghidra
    unknown = tools_for(capa_input([], caps, backend=None))
    assert tool_obs(unknown)[0][1].origins == ('D_ghidra',)  # an unknown backend takes the dependent tag


def test_capa_unlocalized_never_attaches():
    """File-scope matches, matches without a function and links that merely carry an address name no candidate."""
    file_scope = capability('newer', 'persist via run key', link('newer', None, 'none'), scope='file')
    stray = capability('newer', 'inject code', link('newer', RVA_NEWER, 'none'), scope='instruction')
    source = tools_for(capa_input([], [file_scope, stray]))
    every_key = [c.candidate_key for c in GhidriffPairing(resolve()).candidates()]
    assert tool_obs(source, every_key) == []
    pair = {o.ref.id: o for o in source.pair_observations()}
    assert set(pair) == {'persist via run key', 'inject code'}
    assert all(o.kind == 'capa:unlocalized-added' and o.role == 'context' and o.nav is None for o in pair.values())
    assert pair['inject code'].detail == 'capa matches inject code in the newer build without a function'


def test_capa_newly_detectable_in_an_unchanged_function_is_not_change_evidence():
    unchanged = Candidate(candidate_key='1' * 64, older=(FunctionRef(rva=0x1300),), newer=(FunctionRef(rva=0x1380),))
    pairing = project_pairing(unchanged=[(0x1300, 0x1380)])
    source = tools_for(capa_input([], [capability('newer', AES, link('newer', 0x1380))], pairing=pairing),
                       candidates=[unchanged])
    assert tool_obs(source, ['1' * 64]) == [] and list(source.pair_observations()) == []


def test_capa_library_matches_and_unchanged_rules_are_not_evidence():
    same = capability('older', AES, link('older', 0x1000)), capability('newer', AES, link('newer', 0x1080))
    library = capability('newer', 'contains zlib', link('newer', RVA_NEWER), kind='library')
    source = tools_for(capa_input([same[0]], [same[1], library]))
    assert tool_obs(source) == [] and list(source.pair_observations()) == []


def test_capa_without_a_function_pairing_places_nothing():
    source = tools_for(capa_input([], [capability('newer', AES, link('newer', RVA_NEWER))],
                                  pairing=FunctionPairing.empty()))
    assert tool_obs(source) == []
    status = {s.channel: s for s in source.statuses()}['capa']
    assert status.state == 'partial' and 'pairing' in status.reason


def test_floss_static_string_never_attributed():
    """A static string has an offset, not a function; even a link that carries a function's RVA names no candidate."""
    static = string('newer', 'Dropped oversize fragment', 'static',
                    EvidenceLink(tool_run_id='floss-newer', artifact_sha256=NEW_SHA, rva=RVA_NEWER, file_offset=0x600))
    language = string('newer', 'Fehler', 'language', link('newer', RVA_NEWER, engine='floss'))  # inconsistent input
    source = tools_for(floss_input([], [static, language]))
    assert tool_obs(source) == [] and list(source.pair_observations()) == []


def test_floss_stack_tight_and_decoded_strings_attach_to_their_function_as_context():
    stack = string('newer', 'cmd.exe', 'stack', link('newer', RVA_NEWER, 'stack-frame', engine='floss'))
    decoded = string('newer', 'http://x', 'decoded', link('newer', 0x1700, 'decoding-routine', engine='floss'))
    gone = string('older', 'old tight', 'tight', link('older', 0x1000, 'stack-frame', engine='floss'))
    found = dict(((k, o.kind), o) for k, o in tool_obs(tools_for(floss_input([gone], [stack, decoded]))))
    assert set(found) == {(READ_KEY, 'str:added'), (VER_KEY, 'str:added'), (READ_KEY, 'str:removed')}
    added = found[(READ_KEY, 'str:added')]
    assert (added.role, added.channel, added.verification, added.origins) == ('context', 'strings', 'tool-reported',
                                                                              ('D_bytes',))
    assert added.ref.kind == 'floss-string' and added.ref.sha256 == hashlib.sha256(b'cmd.exe').hexdigest()
    assert added.detail == 'stack string added: cmd.exe' and added.nav == Nav(side='newer', rva=RVA_NEWER)
    assert found[(VER_KEY, 'str:added')].detail == 'decoded string added: http://x'


def test_floss_secret_looking_strings_are_never_shown():
    secret = 'password=hunter2hunter2'
    stack = string('newer', secret, 'stack', link('newer', RVA_NEWER, 'stack-frame', engine='floss'))
    stack = stack.model_copy(update={'secret_kind': 'credential-assignment'})
    [(_, obs)] = tool_obs(tools_for(floss_input([], [stack], show_secrets=True)))
    assert 'hunter2' not in obs.detail and 'credential-assignment' in obs.detail


@pytest.mark.parametrize('flag,kind', [('toolchain-changed', 'die:toolchain-changed'), ('packed', 'die:packed'),
                                       ('protected', 'die:protected')], ids=['toolchain', 'packed', 'protected'])
def test_die_flags_are_pair_context_that_applies_to_every_lead(flag, kind):
    quality = QualityFlag(code=flag, source='diec', detail='older: MSVC 19.29 | newer: MSVC 19.34')
    source = tools_for(tool_input('diec', evidence('diec', 'older'), evidence('diec', 'newer'), flags=[quality]))
    [obs] = source.pair_observations()
    assert (obs.kind, obs.role, obs.channel, obs.verification) == (kind, 'context', 'build', 'tool-reported')
    assert obs.origins == ('D_compiler',) and obs.evidence_class == 'E-BUILD' and obs.nav is None
    assert obs.ref == ObsRef(kind='die-flag', id=flag) and obs.detail == 'older: MSVC 19.29 | newer: MSVC 19.34'
    assert tool_obs(source) == []  # a build fact belongs to no function


def test_die_heuristic_only_detections_are_ignored():
    quality = QualityFlag(code='heuristic-only', source='diec', detail='weak heuristic detections: older: x')
    source = tools_for(tool_input('diec', evidence('diec', 'older'), evidence('diec', 'newer'), flags=[quality]))
    assert list(source.pair_observations()) == []


def test_die_environment_unknown_makes_the_build_channel_partial_not_a_clean_no():
    quality = QualityFlag(code='environment-unknown', source='diec', detail='no signature-level toolchain detection')
    source = tools_for(tool_input('diec', evidence('diec', 'older'), evidence('diec', 'newer'), flags=[quality]))
    status = {s.channel: s for s in source.statuses()}['build']
    assert status.state == 'partial' and 'toolchain' in status.reason and list(source.pair_observations()) == []


def test_flags_repeated_on_every_delta_are_listed_once():
    quality = QualityFlag(code='toolchain-changed', source='diec', detail='a | b')
    carriers = [tool_input('diec', evidence('diec', 'older'), evidence('diec', 'newer'), flags=[quality]),
                capa_input([], [], flags=[quality])]  # the CLI hands the whole flag set to every engine's delta
    assert len(list(tools_for(*carriers).pair_observations())) == 1


def test_capa_quality_flags_become_capa_context():
    limit = QualityFlag(code='capa-limitation', source='capa', detail='older: some limitation rule')
    shift = QualityFlag(code='function-recovery-shift', source='capa', detail='capa recovered 10 and 30 functions')
    source = tools_for(capa_input([], [], flags=[limit, shift]))
    found = {o.kind: o for o in source.pair_observations()}
    assert set(found) == {'capa:limitation', 'capa:recovery-shift'}
    assert all(o.channel == 'capa' and o.role == 'context' for o in found.values())
    assert {s.channel: s for s in source.statuses()}['capa'].state == 'partial'  # a limitation rule fired: not complete


def test_unlocalized_pair_observations_are_capped_and_the_cut_is_reported():
    many = [capability('newer', f'rule {i:03d}', link('newer', None, 'none'), scope='file')
            for i in range(MAX_PAIR_OBSERVATIONS + 3)]
    source = tools_for(capa_input([], many))
    assert len(list(source.pair_observations())) == MAX_PAIR_OBSERVATIONS
    assert '3 unlocalized' in {s.channel: s for s in source.statuses()}['capa'].reason


def test_statuses_follow_what_ran_and_come_in_channel_order():
    nothing = tools_for()
    assert [(s.channel, s.state) for s in nothing.statuses()] == [('strings', 'not-run'), ('capa', 'not-run'),
                                                                  ('build', 'not-run')]
    assert nothing.cache_keys() == () and list(nothing.pair_observations()) == [] and tool_obs(nothing) == []
    ran = tools_for(capa_input([], [capability('newer', AES, link('newer', RVA_NEWER))]))
    assert {s.channel: s.state for s in ran.statuses()} == {'strings': 'not-run', 'capa': 'available',
                                                            'build': 'not-run'}


def test_a_failed_or_unsupported_run_is_reported_not_read_as_clean():
    older, newer = tool_run('capa', 'older', status='failed'), tool_run('capa', 'newer')
    failed = ToolInput('capa', None, older, newer)
    unsupported = ToolInput('floss', None, tool_run('floss', 'older', status='unsupported'), tool_run('floss', 'newer'))
    source = tools_for(failed, unsupported)
    states = {s.channel: (s.state, s.reason) for s in source.statuses()}
    assert states['capa'] == ('failed', 'capa older run failed') and states['strings'][0] == 'unsupported'


def test_tool_results_that_cannot_be_compared_are_unsupported():
    mismatch = tool_input('capa', evidence('capa', 'older'), evidence('capa', 'newer'))
    changed = mismatch.delta.model_copy(update={'comparable': False, 'reasons': ('tool configuration differs: version',)})
    source = tools_for(ToolInput('capa', changed, mismatch.older_run, mismatch.newer_run))
    capa = {s.channel: s for s in source.statuses()}['capa']
    assert (capa.state, capa.reason) == ('unsupported', 'tool configuration differs: version')


def test_a_truncated_tool_result_is_partial():
    changed = capa_input([], []).delta.model_copy(update={'truncated': True})
    source = tools_for(ToolInput('capa', changed, tool_run('capa', 'older'), tool_run('capa', 'newer')))
    assert {s.channel: s for s in source.statuses()}['capa'].state == 'partial'


def test_cache_keys_name_every_run_that_was_used_sorted():
    source = tools_for(floss_input(), capa_input())
    expected = tuple(ToolKey(engine=engine, side=side, cache_key='c' * 64)  # PilotInputs sorts by (engine, side)
                     for engine in ('capa', 'floss') for side in ('newer', 'older'))
    assert source.cache_keys() == expected


@pytest.mark.parametrize('older_sha,newer_sha,code,reason', [
    (NEW_SHA, OLD_SHA, 'PT-PILOT-ORIENTATION', 'tool-orientation'),
    ('c' * 64, NEW_SHA, 'PT-PILOT-MISMATCH', 'tool-artifact'),
    (OLD_SHA, 'c' * 64, 'PT-PILOT-MISMATCH', 'tool-artifact'),
], ids=['swapped', 'older-foreign', 'newer-foreign'])
def test_tool_runs_of_other_artifacts_are_refused(older_sha, newer_sha, code, reason):
    item = ToolInput('capa', None, tool_run('capa', 'older', sha=older_sha), tool_run('capa', 'newer', sha=newer_sha))
    with pytest.raises(PilotError) as info:
        tools_for(item)
    assert (info.value.code, info.value.reason) == (code, reason)


def test_inconsistent_tool_inputs_are_refused():
    good = capa_input()
    cases = {
        'tool-engine': ToolInput('floss', good.delta, good.older_run, good.newer_run),
        'tool-runs-missing': ToolInput('capa', good.delta, None, good.newer_run),
        'tool-run-side': ToolInput('capa', good.delta, good.newer_run, good.older_run),
    }
    for reason, item in cases.items():
        with pytest.raises(PilotError) as info:
            tools_for(item)
        assert info.value.reason == reason, reason
    with pytest.raises(PilotError) as info:
        tools_for(good, good)
    assert info.value.reason == 'duplicate-tool-input'


def test_tool_observations_pass_the_contract_and_are_deterministic():
    inputs = (capa_input([], [capability('newer', AES, link('newer', RVA_NEWER)),
                             capability('newer', 'file rule', link('newer', None, 'none'), scope='file')]),
              floss_input([], [string('newer', 'cmd.exe', 'stack', link('newer', RVA_NEWER, 'stack-frame',
                                                                       engine='floss'))]))
    base = tools_for(*inputs)
    expected = ([(k, o.obs_id) for k, o in tool_obs(base)], [o.obs_id for o in base.pair_observations()])
    assert expected[0] and expected[1]
    assert all(keys.observation_id(o) == o.obs_id for _, o in tool_obs(base))
    assert ([(k, o.obs_id) for k, o in tool_obs(tools_for(*reversed(inputs)))],
            [o.obs_id for o in tools_for(*reversed(inputs)).pair_observations()]) == expected


# --- the unified result: rows as candidates, ChangeFacts as typed observations --------------------------------------------
# Results are written with the real `unified.store` and read back through it (the only way PIL may read them).

RAW_SHA = 'c' * 64
UNI_KEYS = {name: key_of(*sides) for name, sides in {
    'read': ([0x1000], [RVA_NEWER]), 'ver': ([0x1600], [0x1700]), 'review': ([0x1200], [0x1280]),
    'same': ([0x1300], [0x1380]), 'fight': ([0x1500], [0x1540]), 'added': ([], [0x1800]),
    'removed': ([0x1400], [])}.items()}


def side_refs(rvas, name: str | None = None) -> tuple[SideRef, ...]:
    return tuple(SideRef(rva=r, name=name, kind='function') for r in rvas)


def uni_row(older, newer, decision: str = 'matched', materiality: str = 'unknown', *, name: str | None = None,
            flags=(), classes=(), contest=None, atoms=()) -> UnifiedMatch:
    return UnifiedMatch(row_id=unified_keys.row_id(OLD_SHA, NEW_SHA, older, newer), older=side_refs(older, name),
                        newer=side_refs(newer, name), decision=decision, materiality=materiality, atoms=atoms,
                        flags=tuple(flags), change_classes=tuple(classes), contest=contest)


def facts_of(row: UnifiedMatch, verdict: str, *, proof=None, second=None, states=None, deltas=(), eh='absent',
             targets=(0, 0, 0)) -> ChangeFacts:
    channels = tuple((c, (states or {}).get(c, 'unavailable')) for c in UNI_CHANNELS)
    return ChangeFacts(row_id=row.row_id, verdict=verdict, proof=proof, second_channel=second, channels=channels,
                       targets=targets, eh=eh, deltas=tuple(deltas))


def delta_of(cls: str, channel: str, older=None, newer=None, old=None, new=None) -> Delta:
    return Delta(cls=cls, channel=channel, older_rva=older, newer_rva=newer, old=old, new=new)


def uni_scenario(names: str | None = 'read_item') -> tuple[list[UnifiedMatch], list[ChangeFacts]]:
    read = uni_row([0x1000], [RVA_NEWER], materiality='material', name=names)
    ver = uni_row([0x1600], [0x1700], materiality='cosmetic')
    review = uni_row([0x1200], [0x1280], 'tentative', 'review', classes=('address-only', 'constant'))
    same = uni_row([0x1300], [0x1380], materiality='unchanged')
    weak = Atom(source='ghidriff', step='x', tier='C', cardinality='1:1', cls='E-NAME', older_rva=0x1500,
                newer_rva=0x1540)
    fight = uni_row([0x1500], [0x1540], 'contested', 'unknown', contest=Contest(strength='weak', against=(0,)),
                    atoms=(weak,))
    added = uni_row([], [0x1800], 'newer-only', 'not-applicable', flags=('thunk', 'truncated'))
    removed = uni_row([0x1400], [], 'older-only', 'not-applicable')
    rows = [read, ver, review, same, fight, added, removed]
    facts = [
        facts_of(read, 'material', second='C6', states={'C2': 'differs', 'C6': 'differs'},
                 deltas=[delta_of('comparison', 'C2', 0x1000, RVA_NEWER, '>', '>='),
                         delta_of('call-added', 'C4', None, RVA_NEWER, None, 'RtlSizeTAdd')]),
        facts_of(ver, 'cosmetic', proof='COS-LAYOUT/1', deltas=[delta_of('block-added', 'C3', None, 0x1700)]),
        facts_of(review, 'review', states={'C5': 'differs'},
                 deltas=[delta_of('constant', 'C5', 0x1200, 0x1280, '0x40', '0x80'),
                         delta_of('string', 'C5', None, 0x1280, None, '"Dropped"'),
                         delta_of('register-only', 'C2', 0x1200, 0x1280, 'rax', 'rcx')]),
        facts_of(same, 'unchanged', proof='UNCH/1', states={'C0': 'equal'}),
        facts_of(added, 'not-applicable', states={c: 'not-applicable' for c in UNI_CHANNELS}),
        facts_of(removed, 'not-applicable', states={c: 'not-applicable' for c in UNI_CHANNELS})]
    return rows, facts


def write_loaded(directory: Path, rows, facts, *, status: str = 'complete', limitations=(), ir: bool = False,
                 older: str = OLD_SHA, newer: str = NEW_SHA, state: str = 'current') -> LoadedResult:
    directory.mkdir(parents=True, exist_ok=True)
    ref = IrRef(ir_key='1' * 64, content_digest='2' * 64, producer_mode='gzf', functions=7) if ir else None
    source = SourceRef(source='ghidriff', entry_id=RUN, file_sha256=RAW_SHA, version='1')
    manifest = store.write_result(
        directory, older_sha256=older, newer_sha256=newer, ghidriff_run_id=RUN, ghidriff_raw_sha256=RAW_SHA,
        ir_older=ref, ir_newer=ref, sources=(source,), manual_digest=unified_keys.manual_digest([]),
        config_digest='d' * 64, status=status, limitations=limitations, rows=rows, facts=facts,
        created_utc='2026-10-14T12:00:00+00:00')
    return LoadedResult(state=state, reason=None, manifest=manifest, directory=directory)


@pytest.fixture
def uni(tmp_path):
    rows, facts = uni_scenario()
    return write_loaded(tmp_path / 'result', rows, facts)


def view_of(loaded: LoadedResult, **kw) -> UnifiedView:
    return UnifiedView.read(loaded, older_sha256=OLD_SHA, newer_sha256=NEW_SHA, **kw)


def uni_obs(source, name_keys=None) -> dict[str, list[Observation]]:
    wanted = list(UNI_KEYS.values()) if name_keys is None else name_keys
    return grouped(source, wanted)


def test_unified_rows_are_the_candidates_with_the_identity_map(uni):
    pairing = UnifiedPairing(view_of(uni))
    found = candidates_of(pairing)
    assert set(found) == set(UNI_KEYS.values()) and list(found) == sorted(found)
    expected = {'read': 'corroborated', 'ver': 'corroborated', 'same': 'corroborated', 'review': 'unassessed',
                'fight': 'contested', 'added': 'unassessed', 'removed': 'unassessed'}
    assert {name: found[UNI_KEYS[name]].identity for name in UNI_KEYS} == expected
    read = found[UNI_KEYS['read']]
    assert (read.older[0].rva, read.older[0].name, read.newer[0].rva) == (0x1000, 'read_item', RVA_NEWER)
    assert found[UNI_KEYS['added']].older == () and found[UNI_KEYS['removed']].newer == ()


@pytest.mark.parametrize('decision', get_args(Decision), ids=get_args(Decision))
def test_every_unified_decision_maps_to_an_identity(decision):
    assert IDENTITY_OF_DECISION[decision] in get_args(Identity)
    assert set(IDENTITY_OF_DECISION) == set(get_args(Decision))  # a new decision must be placed on purpose


def test_unified_pairing_names_its_result_and_never_a_secondary_set(uni):
    pairing = UnifiedPairing(view_of(uni))
    assert pairing.unified_result_id() == uni.manifest.result_id and pairing.secondary_set_ids() == ()
    assert pairing.status() == ChannelStatus(channel='pairing', state='available')


def test_a_partial_unified_result_makes_the_pairing_channel_partial(tmp_path):
    rows, facts = uni_scenario()
    partial = write_loaded(tmp_path / 'r', rows, facts, status='partial', limitations=('bindiff-pair-mismatch',))
    status = UnifiedPairing(view_of(partial)).status()
    assert status.state == 'partial' and 'bindiff-pair-mismatch' in status.reason


def test_unified_wide_rows_keep_the_first_functions_and_say_so(tmp_path):
    wide = uni_row([0x1000 + 4 * i for i in range(300)], [0x4000])
    pairing = UnifiedPairing(view_of(write_loaded(tmp_path / 'r', [wide], [])))
    [candidate] = list(pairing.candidates())
    assert candidate.candidate_key == wide.row_id and len(candidate.older) == MAX_SIDE_FUNCTIONS
    assert pairing.status().state == 'partial' and '1 row' in pairing.status().reason


def test_unified_candidates_over_the_limit_fail_loudly(uni):
    with pytest.raises(PilotError) as info:
        view_of(uni, limits=dataclasses.replace(DEFAULT_LIMITS, p01_candidates=3))
    assert (info.value.code, info.value.reason) == ('PT-PILOT-LIMIT', 'candidates')


@pytest.mark.parametrize('state', ['stale', 'none', 'invalid'])
def test_only_a_current_unified_result_is_used(uni, state):
    other = dataclasses.replace(uni, state=state)
    with pytest.raises(PilotError) as info:
        view_of(other)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-STALE', f'unified-{state}')


def test_a_unified_result_of_another_pair_or_orientation_is_refused(tmp_path):
    foreign = write_loaded(tmp_path / 'a', [], [], older='e' * 64, newer='f' * 64)
    with pytest.raises(PilotError) as info:
        view_of(foreign)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-MISMATCH', 'unified-pair')
    reverse = write_loaded(tmp_path / 'b', [], [], older=NEW_SHA, newer=OLD_SHA)
    with pytest.raises(PilotError) as info:
        view_of(reverse)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-ORIENTATION', 'unified-orientation')


def test_a_damaged_unified_part_is_a_storage_error_not_a_crash(uni):
    part = uni.directory / 'rows.jsonl.gz'
    part.write_bytes(part.read_bytes()[:40])
    with pytest.raises(PilotError) as info:
        view_of(uni)
    assert (info.value.code, info.value.reason) == ('PT-PILOT-STORAGE', 'unified-read')


def test_cosmetic_proof_becomes_conflict(uni):
    """A named cosmetic proof is kept as a conflict next to the B1 guard it contradicts: never dropped, never a shape."""
    guarded = fmatch('m-ver', 'modified', [rec('older', 'get_version', 0x1600, code=GUARD_OLD)],
                     [rec('newer', 'get_version', 0x1700, code=GUARD_NEW)])
    matches = [read_item(), guarded]
    code = CodeEvidence(B1Evidence(resolve(matches), signal_sets(matches)), UnifiedFacts(view_of(uni)))
    found = grouped(code, [UNI_KEYS['ver']])[UNI_KEYS['ver']]
    assert {o.kind: o.role for o in found} == {'b1:BND': 'shape', 'b1:ERR': 'shape', 'cf:cosmetic': 'conflict'}
    cosmetic = next(o for o in found if o.kind == 'cf:cosmetic')
    assert (cosmetic.channel, cosmetic.verification, cosmetic.origins, cosmetic.evidence_class) == (
        'code', 'tool-reported', ('D_ghidra',), 'E-LAYOUT')
    assert cosmetic.ref == ObsRef(kind='change-facts', id=UNI_KEYS['ver']) and cosmetic.nav == Nav(side='newer', rva=0x1700)
    assert cosmetic.detail == 'proof COS-LAYOUT/1 holds: the change is cosmetic' and not cosmetic.obligations
    assert 'cf:block-added' not in {o.kind for o in found}  # the deltas of a proven row are part of the proof


def test_an_unchanged_proof_is_a_conflict_too(uni):
    [obs] = uni_obs(UnifiedFacts(view_of(uni)))[UNI_KEYS['same']]
    assert (obs.kind, obs.role, obs.evidence_class) == ('cf:unchanged', 'conflict', 'E-BODY')
    assert obs.detail == 'proof UNCH/1 holds: the code is unchanged'


def test_a_decompiler_relative_proof_says_so(tmp_path):
    row = uni_row([0x1000], [0x1080], materiality='cosmetic')
    facts = facts_of(row, 'cosmetic', proof='COS-PSEUDO/1', states={'C6': 'equal'})
    [obs] = grouped(UnifiedFacts(view_of(write_loaded(tmp_path / 'r', [row], [facts]))), [row.row_id])[row.row_id]
    assert obs.evidence_class == 'E-DECOMP' and obs.detail.endswith('(decompiler-relative)')


def test_material_deltas_are_typed_shape_observations(uni):
    found = {o.kind: o for o in uni_obs(UnifiedFacts(view_of(uni)))[UNI_KEYS['read']]}
    assert set(found) == {'cf:comparison', 'cf:call-added'}
    comparison = found['cf:comparison']
    assert (comparison.role, comparison.channel, comparison.verification, comparison.origins,
            comparison.evidence_class, comparison.obligations) == ('shape', 'code', 'tool-reported', ('D_ghidra',),
                                                                   'E-BODY', ())
    assert comparison.ref == ObsRef(kind='change-facts', id=UNI_KEYS['read'], pointer='/deltas/0')
    assert comparison.nav == Nav(side='newer', rva=RVA_NEWER) and comparison.detail == 'comparison: > -> >='
    call = found['cf:call-added']
    assert call.evidence_class == 'E-CALL' and call.detail == 'call-added: RtlSizeTAdd'
    assert call.ref.pointer == '/deltas/1'


def test_a_removed_delta_is_located_on_the_older_function(tmp_path):
    row = uni_row([0x1000], [0x1080], materiality='material')
    facts = facts_of(row, 'material', second='C6', states={'C4': 'differs', 'C6': 'differs'},
                     deltas=[delta_of('call-removed', 'C4', 0x1010, None, 'puts', None)])
    [obs] = grouped(UnifiedFacts(view_of(write_loaded(tmp_path / 'r', [row], [facts]))), [row.row_id])[row.row_id]
    assert (obs.kind, obs.nav, obs.detail) == ('cf:call-removed', Nav(side='older', rva=0x1010), 'call-removed: was puts')


def test_review_deltas_say_that_no_second_channel_anchors_them(uni):
    found = {o.kind: o for o in uni_obs(UnifiedFacts(view_of(uni)))[UNI_KEYS['review']]}
    assert set(found) == {'cf:constant', 'cf:string', 'cf:register-only', 'cf:address-only'}
    assert found['cf:constant'].role == 'shape' and found['cf:constant'].obligations == ('second-channel',)
    assert found['cf:string'].role == 'context'  # an added string is context, never a fit
    assert found['cf:register-only'].role == found['cf:address-only'].role == 'context'
    assert found['cf:address-only'].detail == 'row class address-only: no code change was listed'
    assert found['cf:constant'].detail == 'constant: 0x40 -> 0x80'


def test_row_flags_are_context_on_the_pairing_channel(uni):
    found = {o.kind: o for o in uni_obs(UnifiedFacts(view_of(uni)))[UNI_KEYS['added']]}
    assert set(found) == {'pair:thunk', 'pair:truncated'}
    assert all(o.role == 'context' and o.channel == 'pairing' and o.origins == ('D_ghidra',) for o in found.values())
    assert found['pair:thunk'].detail == 'thunk: a jump to another function'
    assert found['pair:truncated'].detail == 'code was cut at the scan limit'


def test_row_flags_are_nuisance_or_data_quality():
    assert set(NUISANCE_FLAGS).isdisjoint(QUALITY_FLAGS)
    assert set(NUISANCE_FLAGS) | set(QUALITY_FLAGS) | {'pdata-confirmed'} == set(get_args(RowFlag))


def test_rows_without_applicable_facts_say_nothing(uni):
    found = uni_obs(UnifiedFacts(view_of(uni)))
    assert not [o for o in found.get(UNI_KEYS['removed'], []) if o.kind.startswith('cf:')]  # not-applicable
    assert UNI_KEYS['fight'] not in found  # a contested row without facts: unknown, not a clean no


def test_unified_facts_name_the_s0_ceiling_until_the_program_ir_is_there(uni, tmp_path):
    status = UnifiedFacts(view_of(uni)).status()
    assert status.channel == 'code' and status.state == 'partial' and 'ProgramIR' in status.reason
    rows, facts = uni_scenario()
    with_ir = write_loaded(tmp_path / 'ir', rows, facts, ir=True)
    assert UnifiedFacts(view_of(with_ir)).status() == ChannelStatus(channel='code', state='available')
    partial = write_loaded(tmp_path / 'p', rows, facts, ir=True, status='partial', limitations=('pdata-missing',))
    assert UnifiedFacts(view_of(partial)).status().state == 'partial'


def test_typed_facts_lift_the_text_only_ceiling_but_s0_facts_stay_partial(uni, tmp_path):
    rows, facts = uni_scenario()
    typed = CodeEvidence(b1(), UnifiedFacts(view_of(write_loaded(tmp_path / 'ir', rows, facts, ir=True))))
    assert typed.status() == ChannelStatus(channel='code', state='available')
    s0 = CodeEvidence(b1(), UnifiedFacts(view_of(uni))).status()
    assert s0.state == 'partial' and 'ProgramIR' in s0.reason and TEXT_ONLY_REASON not in s0.reason


def test_unified_output_does_not_depend_on_row_order(tmp_path):
    rows, facts = uni_scenario()
    base = view_of(write_loaded(tmp_path / 'a', rows, facts))
    expected = ([(k, o.obs_id) for k, o in UnifiedFacts(base).observations(UNI_KEYS.values())],
                [c.candidate_key for c in UnifiedPairing(base).candidates()])
    assert expected[0] and len(expected[1]) == 7
    for seed in range(4):
        shuffled_rows, shuffled_facts = list(rows), list(facts)
        random.Random(seed).shuffle(shuffled_rows)
        random.Random(seed + 9).shuffle(shuffled_facts)
        view = view_of(write_loaded(tmp_path / f'b{seed}', shuffled_rows, shuffled_facts))
        assert ([(k, o.obs_id) for k, o in UnifiedFacts(view).observations(UNI_KEYS.values())],
                [c.candidate_key for c in UnifiedPairing(view).candidates()]) == expected


def test_unified_text_is_plain_and_bounded(tmp_path):
    row = uni_row([0x1000], [0x1080], materiality='material', name='f\u202e<b>x</b>')
    facts = facts_of(row, 'material', second='C6', states={'C4': 'differs', 'C6': 'differs'},
                     deltas=[delta_of('callee', 'C4', 0x1000, 0x1080, 'a\nb', '\u202eevil' + 'z' * 100)])
    view = view_of(write_loaded(tmp_path / 'r', [row], [facts]))
    [candidate] = list(UnifiedPairing(view).candidates())
    [obs] = grouped(UnifiedFacts(view), [row.row_id])[row.row_id]
    assert '\u202e' not in candidate.older[0].name and '<b>x</b>' in candidate.older[0].name
    assert len(obs.detail) <= 300 and '\n' not in obs.detail and '\u202e' not in obs.detail


def test_tool_evidence_attaches_to_unified_candidates_as_well(uni):
    """The candidate index is universe-agnostic: the same functions are the same candidates in either universe."""
    index = CandidateIndex(UnifiedPairing(view_of(uni)).candidates())
    capa = capa_input([], [capability('newer', AES, link('newer', RVA_NEWER))])
    source = ToolDeltas([capa], index, older_sha256=OLD_SHA, newer_sha256=NEW_SHA)
    assert [(k, o.kind) for k, o in tool_obs(source, list(UNI_KEYS.values()))] == [(UNI_KEYS['read'], 'capa:added')]
    assert UNI_KEYS['read'] == READ_KEY  # a Ghidriff row and the unified row of the same functions are one candidate


# --- a synthetic project end to end --------------------------------------------------------------------------------------


def open_overview(service, side: str) -> PeOverview:
    artifact = next(a for a in service.project.artifacts if a.side == side)
    with VerifiedArtifactReader.open_artifact(artifact, service.root) as reader:
        return inspect_pe(reader)


def test_a_synthetic_project_runs_through_the_code_side_adapters(tmp_path):
    service = make_project(tmp_path / 'p')
    try:
        project, run = service.project, service.project.runs[-1]
        sha = {a.side: a.sha256 for a in project.artifacts}
        older, newer = open_overview(service, 'older'), open_overview(service, 'newer')
        matches = [m for m in project.matches if m.run_id == run.id]
        rows = GhidriffRows.resolve(sha['older'], sha['newer'], matches, pe.address_map(older, newer))
        assert (len(rows.rows), rows.unresolved, rows.state) == (5, 0, 'available')
        read = keys.candidate_key(sha['older'], sha['newer'], [0x1000], [0x1080])
        pairing = GhidriffPairing(rows)
        assert read in candidates_of(pairing) and {c.identity for c in pairing.candidates()} == {'unassessed'}
        sets = [signals.detect(view) for view in build_views(project, run.id).matches]
        assert B1Evidence(rows, sets).status() == ChannelStatus(channel='code', state='available')
        calls = GhidriffCalls(rows, pe.import_delta(older, newer))
        assert [(k, o.kind, o.verification) for k, o in calls.observations([read])] == [
            (read, 'call:added', 'label-only')]  # read_item gained a call to report_invalid_index
        assert list(calls.observations([c.candidate_key for c in pairing.candidates() if c.candidate_key != read])) == []
        assert calls.status().state == 'partial'
    finally:
        service.close()


def test_a_real_s0_unified_result_feeds_the_adapters(tmp_path):
    """The real pipeline (in process, S0 mode) on the synthetic project, read back through `unified.store`."""
    service = make_project(tmp_path / 'p')
    try:
        pipeline.run_unified(service, UnifiedOptions(isolate=False))
        loaded = pipeline.load_current(service, pipeline.make_plan(service))
        assert loaded.state == 'current'
        project = service.project
        sha = {a.side: a.sha256 for a in project.artifacts}
        view = UnifiedView.read(loaded, older_sha256=sha['older'], newer_sha256=sha['newer'])
        found = candidates_of(UnifiedPairing(view))

        def key(older, newer):
            return keys.candidate_key(sha['older'], sha['newer'], [older], [newer])
        read, ver, fmt = key(0x1000, 0x1080), key(0x1600, 0x1700), key(0x1200, 0x1280)
        assert len(found) == 6 and found[read].identity == 'corroborated'
        rows = GhidriffRows.resolve(sha['older'], sha['newer'], [m for m in project.matches
                                                                  if m.run_id == project.runs[-1].id],
                                    pe.address_map(open_overview(service, 'older'), open_overview(service, 'newer')))
        assert {r.candidate_key for r in rows.rows} <= set(found)  # the same pairs are the same candidates
        facts = grouped(UnifiedFacts(view), list(found))
        assert {o.kind: (o.role, o.obligations) for o in facts[read]} == {'cf:call-added': ('shape', ())}
        assert {o.kind: (o.role, o.obligations) for o in facts[ver]} == {'cf:constant': ('shape', ('second-channel',))}
        assert {o.kind: o.role for o in facts[fmt]} == {'cf:cosmetic': 'conflict', 'cf:address-only': 'context'}
        assert UnifiedFacts(view).status().state == 'partial'  # S0: no ProgramIR
    finally:
        service.close()


# --- purity, wording and ordering across every adapter -----------------------------------------------------------------

MODULES = ('pe', 'code', 'calls', 'tools', 'unified')
FORBIDDEN = {'PySide6', 'shiboken6', 'subprocess', 'socket', 'ssl', 'urllib', 'http', 'ctypes', 'sqlite3', 'os',
             'threading', 'multiprocessing'}
# Reading goes through public data contracts and `unified.store` (the one sanctioned reader); nothing that opens the
# project database, spawns a process, builds a widget or runs the pipeline.
ALLOWED = ('patchtrace.enrichment.contracts', 'patchtrace.enrichment.signals', 'patchtrace.intelligence.tools.common',
           'patchtrace.intelligence.tools.delta', 'patchtrace.models', 'patchtrace.pe_overview', 'patchtrace.pilot',
           'patchtrace.secondary.contracts', 'patchtrace.secondary.evidence', 'patchtrace.secondary.reconcile',
           'patchtrace.unified.addressing', 'patchtrace.unified.contracts', 'patchtrace.unified.limits',
           'patchtrace.unified.store')


def imported(module: str) -> set[str]:
    tree = ast.parse((SOURCES / f'{module}.py').read_text(encoding='utf-8'))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ''
            if node.level:
                parent = ['patchtrace', 'pilot', 'sources'][:4 - node.level]
                base = '.'.join([*parent, *([base] if base else [])])
            names |= {base, *(f'{base}.{a.name}' for a in node.names)}
    return names


@pytest.mark.parametrize('module', MODULES, ids=MODULES)
def test_adapters_import_only_public_data_contracts(module):
    names = imported(module)
    assert not {n for n in names if n.split('.')[0] in FORBIDDEN}, names
    internal = {n for n in names if n.startswith('patchtrace')}
    assert all(n.startswith(ALLOWED) for n in internal), sorted(n for n in internal if not n.startswith(ALLOWED))


def test_the_sources_package_init_is_documentation_only():
    tree = ast.parse((SOURCES / '__init__.py').read_text(encoding='utf-8'))
    assert all(isinstance(node, ast.Expr) for node in tree.body)


def test_importing_every_adapter_loads_no_qt_process_or_network_client():
    code = ('import sys\nclass Block:\n    def find_spec(self, name, path=None, target=None):\n'
            '        if name.split(".")[0] == "PySide6": raise ImportError("blocked")\n'
            'sys.meta_path.insert(0, Block())\n'
            + ''.join(f'import patchtrace.pilot.sources.{m}\n' for m in MODULES) +
            'bad = [m for m in ("PySide6", "shiboken6", "subprocess", "ssl", "urllib.request", "http.client",\n'
            '                   "patchtrace.jobs", "patchtrace.service", "patchtrace.ui") if m in sys.modules]\n'
            'print(bad)\nraise SystemExit(1 if bad else 0)\n')
    env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
    result = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=env, timeout=120)
    assert result.returncode == 0, result.stdout + result.stderr


def everything(tmp_path) -> tuple[list[ChannelStatus], list[Observation]]:
    """Statuses and observations of every adapter over rich synthetic scenarios (one of each kind)."""
    rows = resolve()
    sets = [bindiff_for((0x1000, RVA_NEWER), (0x1600, 0x1780))]
    pairing = GhidriffPairing(rows, sets)
    lexical = b1(rows)
    rows_u, facts_u = uni_scenario()
    view = view_of(write_loaded(tmp_path / 'u', rows_u, facts_u))
    candidates = [*pairing.candidates(), *UnifiedPairing(view).candidates()]
    imports = imports_delta({'ntoskrnl.exe': ['RtlCopyMemory']}, {'ntoskrnl.exe': ['RtlCopyMemory', 'RtlSizeTAdd']})
    stack = string('newer', 'cmd.exe', 'stack', link('newer', RVA_NEWER, 'stack-frame', engine='floss'))
    quality = [QualityFlag(code='toolchain-changed', source='diec', detail='older: MSVC 19.29 | newer: MSVC 19.34'),
               QualityFlag(code='capa-limitation', source='capa', detail='older: some limitation rule')]
    tools = tools_for(
        capa_input([], [capability('newer', AES, link('newer', RVA_NEWER)),
                        capability('newer', 'file rule', link('newer', None, 'none'), scope='file')], flags=quality),
        floss_input([], [stack]), tool_input('diec', evidence('diec', 'older'), evidence('diec', 'newer'),
                                              flags=quality), candidates=candidates)
    sources = [pairing, UnifiedPairing(view), lexical, UnifiedFacts(view), CodeEvidence(lexical, UnifiedFacts(view)),
               calls_of([call_match(['gone'], ['RtlSizeTAdd'])], imports)]
    statuses = [s.status() for s in sources] + list(tools.statuses())
    keys_ = [c.candidate_key for c in candidates] + [CALL_KEY]
    found = [o for s in sources if hasattr(s, 'observations') for _, o in s.observations(keys_)]
    found += [o for _, o in tools.observations(keys_)] + list(tools.pair_observations())
    return statuses, found


def test_no_adapter_text_uses_a_banned_word_or_markup_control(tmp_path):
    statuses, found = everything(tmp_path)
    texts = [s.reason for s in statuses if s.reason] + [o.detail for o in found]
    assert len(texts) > 20
    for text in texts:
        assert not [w for w in BANNED if w in text.lower()], text
    assert all(keys.observation_id(o) == o.obs_id for o in found)  # every id is the content id
    assert {s.channel for s in statuses} >= {'pairing', 'code', 'calls', 'strings', 'capa', 'build'}


def test_every_adapter_orders_its_output_by_candidate_then_id_and_answers_each_key_once():
    for source in (b1(), calls_of([call_match(['a', 'b'], ['c', 'd']), read_item(['x', 'y'])])):
        wanted = sorted({READ_KEY, CALL_KEY, VER_KEY}, reverse=True)  # asked in the opposite order, one key twice
        got = list(source.observations([*wanted, READ_KEY]))
        assert got and got == sorted(got, key=lambda item: (item[0], item[1].obs_id))
        assert len({(k, o.obs_id) for k, o in got}) == len(got)


def test_a_disagreeing_engine_makes_the_identity_contested_even_when_another_agrees():
    agree, differ = bindiff_for((0x1000, RVA_NEWER)), rzdiff_set([rz(0x1000, 0x1100)])
    found = candidates_of(GhidriffPairing(resolve(), [agree, differ]))
    assert found[READ_KEY].identity == 'contested'  # a contradiction takes priority over a majority (secondary.evidence)


def test_b1_prefers_the_newer_location_and_survives_an_unknown_function():
    signal = read_signal('BND')
    newer = signal.locations[0]
    older = newer.model_copy(update={'side': 'older', 'function_id': 'older-read_item', 'start_line': 1,
                                     'end_line': 2})
    stray = newer.model_copy(update={'function_id': 'someone-else'})

    def only(*locations):
        edited = signal.model_copy(update={'locations': locations})
        sets = [s.model_copy(update={'signals': (edited,)}) if s.match_id == 'm-read' else s for s in signal_sets()]
        return grouped(b1(sets=sets), [READ_KEY])[READ_KEY][0]
    assert only(older, newer).nav == Nav(side='newer', rva=RVA_NEWER, start_line=newer.start_line,
                                         end_line=newer.end_line)
    assert only(older).nav == Nav(side='older', rva=0x1000, start_line=1, end_line=2)
    assert only(stray).nav is None  # the signal still counts; it just cannot navigate


def test_every_adapter_satisfies_its_port(uni):
    view, rows = view_of(uni), resolve()
    assert isinstance(GhidriffPairing(rows), PairingSource) and isinstance(UnifiedPairing(view), PairingSource)
    for source in (b1(rows), UnifiedFacts(view), CodeEvidence(b1(rows))):
        assert isinstance(source, ChangeEvidenceSource)
    assert isinstance(GhidriffCalls(rows), CallDeltaSource) and isinstance(tools_for(), ToolEvidenceSource)


_API = st.sampled_from(['A', 'B', 'C', 'D'])
_TABLES = st.dictionaries(st.sampled_from(['x.dll', 'y.dll']), st.sets(_API, max_size=4).map(sorted), max_size=2)


@settings(max_examples=60, deadline=None, derandomize=True)
@given(older=_TABLES, newer=_TABLES)
def test_import_delta_swaps_added_and_removed_with_the_orientation(older, newer):
    forward = pe.import_delta(overview(older), overview(newer))
    backward = pe.import_delta(overview(newer), overview(older))
    assert (forward.added, forward.removed) == (backward.removed, backward.added)


def test_the_new_files_hold_no_hidden_or_bidirectional_characters():
    """The review that found such characters in other files: scan the sources and this test for Cc, Cf, Zl and Zp."""
    for path in [*SOURCES.glob('*.py'), Path(__file__)]:
        text = path.read_text(encoding='utf-8')
        bad = sorted({hex(ord(c)) for c in text if unicodedata.category(c) in ('Cc', 'Cf', 'Zl', 'Zp')} - {'0xa'})
        assert not bad, (path.name, bad)


def test_the_change_class_tables_cover_the_unified_vocabulary():
    classes, proofs = set(get_args(ChangeClass)), set(get_args(ProofId))
    assert SHAPE_CLASSES < classes and set(NUISANCE_CLASSES) < classes and SHAPE_CLASSES.isdisjoint(NUISANCE_CLASSES)
    assert 'string' not in SHAPE_CLASSES  # an added string is context, whatever else changed
    assert set(EVIDENCE_CLASS_OF_CHANNEL) == set(UNI_CHANNELS) and set(EVIDENCE_CLASS_OF_PROOF) == proofs
    assert set(FLAG_TEXT) == set(NUISANCE_FLAGS) | set(QUALITY_FLAGS)


def test_ghidriff_group_rows_wider_than_the_candidate_limit_keep_the_first_functions():
    wide = fmatch('m-wide', 'split', [rec('older', 'big', 0x1000)],
                  [rec('newer', f'part{i}', 0x1100 + 4 * i, fid=f'n{i}') for i in range(MAX_SIDE_FUNCTIONS + 4)])
    pairing = GhidriffPairing(GhidriffRows.resolve(OLD_SHA, NEW_SHA, [wide], wide_map()))
    [candidate] = list(pairing.candidates())
    assert len(candidate.newer) == MAX_SIDE_FUNCTIONS and candidate.newer[0].rva == 0x1100
    assert pairing.status().state == 'partial' and '1 row' in pairing.status().reason
