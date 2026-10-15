"""R4: the synergy test of docs/specs/program-e/YRX-integration-plan.md section 5 (a known answer) and the byte channel of
`propose` on the SYNTHETIC `capa-api`, `capa-control` and `floss-static` images.

The grid compares five rules, all taken from `term` of the accepted `capa-api` pair, over eleven builds: exact bytes, masked
bytes, an import gate, masked bytes plus the import, and masked bytes plus the call pin. Only the pin, which ties the
masked `call [rip+disp]` back to the TerminateProcess import slot, hits every rebuild and no look-alike. The expected grid
is `tests/fixtures/rules/synergy-matrix.json` and must equal the plan's table; it is scanned by the REAL YARA-X in this
process and, once, through the hidden worker child.

The decoder is the stand-in of `tests/rules_fixtures.py` (iced-x86 is not installed or pinned here; the stand-in equals the
real decoder on these images, see `tests/test_rules_masks.py`). The rules of the grid are written by R1's `synth`; the
reference renderer of the same module is an oracle only, and the grid must equal the one its rules give.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from types import SimpleNamespace

import pytest
import rules_fixtures as rf
from test_rules_masks import body, fake_pair, pe_image, ref, runtime_function, tool_for

from patchtrace.rules import candidates as cd
from patchtrace.rules import gates, runner
from patchtrace.rules.adapters.pe_imports import PeImports
from patchtrace.rules.adapters.tools_delta import CapaCapabilities, FlossStrings, capa_api_names
from patchtrace.rules.candidates import PairCheck, RuleSpec
from patchtrace.rules.contracts import (
    BytesFeature,
    CellResult,
    EngineStamp,
    FunctionRef,
    ImportFeature,
    LintResult,
    StringFeature,
    WorkerRule,
    WorkerTarget,
)
from patchtrace.rules.errors import RuleError
from patchtrace.rules.ports import StringObservation
from patchtrace.rules.window import BytesWindows, WindowSet

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / 'tests' / 'fixtures' / 'rules' / 'synergy-matrix.json'
PLAN = ROOT / 'docs' / 'specs' / 'program-e' / 'YRX-integration-plan.md'
RULES = ('exact bytes', 'masked bytes', 'import only', 'masked + import', 'masked + call-target pin')
LINEAGE = 'a' * 64


@pytest.fixture
def bench(tmp_path):
    bench = rf.Bench(tmp_path)
    yield bench
    bench.close()


@pytest.fixture
def engine():
    pytest.importorskip('yara_x', reason='YARA-X (pip install "patchtrace[rules]") is not installed')
    return pytest.importorskip('patchtrace.rules.engine')


def bytes_source(bench, pair: str = 'capa-api') -> BytesWindows:
    return BytesWindows(rf.SubsetDecoder(), rf.tables_of(bench, pair))


def term_rules(bench, render=cd.synth_renderer) -> dict[str, str]:
    """The five rule texts of the grid, from the window of `term` (the older-build rule of the accepted pair)."""
    pair = rf.capa_pair(bench, 'term')
    (window,) = bytes_source(bench).windows(pair, 'older').windows
    older = bench.build('capa-api', 'older')
    text_at = next(s for s in older.overview.sections if s.name == '.text').raw_offset - 0x1000
    exact = bytes_of(older.data, text_at, window)
    import_gate = ImportFeature(included=True, dll='KERNEL32.dll', name='TerminateProcess', origin='pe-imports',
                                separation='older-only')
    masked = window.model_copy(update={'pins': ()})
    features = {'exact bytes': (exact,), 'masked bytes': (masked,), 'import only': (import_gate,),
                'masked + import': (masked, import_gate), 'masked + call-target pin': (window,)}
    return {name: cd.synth_renderer(RuleSpec(pair, 'older', LINEAGE, found)) for name, found in features.items()}


def bytes_of(data: bytes, text_at: int, window: BytesFeature) -> BytesFeature:
    """The same window with every byte literal (what a rule that does not mask would hold)."""
    raw = data[text_at + window.window_rva:text_at + window.window_rva + window.length]
    return window.model_copy(update={'pattern': ' '.join(f'{b:02X}' for b in raw), 'literal': window.length,
                                     'longest_run': window.length, 'mask': (), 'pins': ()})


def cell_text(cell: CellResult) -> str:
    return 'no-hit' if cell.state == 'no-hit' else f'hit@0x{cell.rvas[0]:x}' if cell.rvas else 'hit'


def scan_grid(rules: dict[str, str], builds: dict[str, bytes], engine) -> dict[str, dict[str, str]]:
    grid = {}
    for name, text in rules.items():
        compiled = engine.RuleSet.compile((WorkerRule(name='x', text=text),))
        assert compiled.lint[0].ok and not compiled.lint[0].warnings, (name, compiled.lint[0])
        grid[name] = {build: cell_text(compiled.scan(data)[0]) for build, data in builds.items()}
    return grid


def test_combined_rule_beats_each_channel_alone(bench, engine):
    grid = scan_grid(term_rules(bench), rf.synergy_builds(bench), engine)
    golden = json.loads(GOLDEN.read_text(encoding='utf-8'))
    assert grid == golden['rules'] and list(next(iter(grid.values()))) == golden['builds']
    assert list(grid) == list(RULES)


def test_the_reference_renderer_is_an_oracle_for_the_production_grid(bench, engine):
    builds = rf.synergy_builds(bench)
    assert scan_grid(term_rules(bench, rf.render_rule), builds, engine) == scan_grid(term_rules(bench), builds, engine)


def plan_table() -> dict[str, list[int]]:
    """The 0/1 rows of the plan's section 5 table (the plan is the specification of the known answer)."""
    rows, lines = {}, PLAN.read_text(encoding='utf-8').splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith('| rule | V1 | V1r |'))
    for line in lines[start + 2:]:
        if not line.startswith('|'):
            break
        cells = [c.strip() for c in line.strip('|').split('|')]
        rows[cells[0]] = [int(c) for c in cells[1:]]
    return rows


def test_the_golden_grid_is_the_table_of_the_plan(bench, engine):
    table, golden = plan_table(), json.loads(GOLDEN.read_text(encoding='utf-8'))
    assert list(table) == ['exact bytes', 'masked bytes', 'import only', 'masked + import', 'masked + call-target pin']
    for name, plan_row in table.items():
        grid = golden['rules'][name]
        named = [int(grid[b] != 'no-hit') for b in ('V1', 'V1r', 'V1t', 'V2', 'LA', 'IMP', 'BOTH')]
        clean = {int(grid[b] != 'no-hit') for b in golden['builds'] if b.startswith('clean-')}
        assert named + [*clean] == plan_row and len(clean) == 1, name


def test_the_grid_through_the_hidden_worker_is_the_same(bench, engine, tmp_path):
    rules, builds = term_rules(bench), rf.synergy_builds(bench)
    targets = []
    for name, data in builds.items():
        path = tmp_path / f'{name}.bin'
        path.write_bytes(data)
        targets.append(WorkerTarget(target_id=name, path=str(path), sha256=hashlib.sha256(data).hexdigest(),
                                    size=len(data)))
    outcome = runner.scan([WorkerRule(name=f'r{i}', text=t) for i, t in enumerate(rules.values())], targets)
    assert all(lint.ok and not lint.warnings for lint in outcome.lint)
    cells = iter(outcome.cells)
    grid = {rule: {} for rule in rules}
    for build in builds:
        for rule in rules:
            grid[rule][build] = cell_text(next(cells))
    assert grid == scan_grid(rules, builds, engine)


def test_masks_make_rebuild_stable(bench, engine):
    grid = scan_grid(term_rules(bench), rf.synergy_builds(bench), engine)
    assert grid['exact bytes']['V1r'] == 'no-hit' and grid['exact bytes']['V1'] == 'hit@0x104d'
    assert grid['masked bytes']['V1r'] == 'hit@0x108d'      # the rebuild moved the function by 0x40 and rewrote its IAT
    assert grid['masked bytes']['V1t'] == 'hit@0x104d'      # another toolchain layout, the same code
    for name in RULES[1:]:
        assert grid[name]['V1r'] != 'no-hit', name


def test_call_pin_removes_conjunction_false_positive(bench, engine):
    grid = scan_grid(term_rules(bench), rf.synergy_builds(bench), engine)
    shape_here_import_there = 'BOTH'      # LA's function (the shape, calling CloseHandle) plus IMP's code (the import)
    assert grid['masked + import'][shape_here_import_there] != 'no-hit'
    assert grid['masked + call-target pin'][shape_here_import_there] == 'no-hit'
    assert grid['masked bytes']['LA'] != 'no-hit' and grid['masked + import']['LA'] == 'no-hit'
    assert grid['import only']['IMP'] != 'no-hit' and grid['masked bytes']['IMP'] == 'no-hit'
    positives = {build for build, state in grid['masked + call-target pin'].items() if state != 'no-hit'}
    assert positives == {'V1', 'V1r', 'V1t'}                  # three of three rebuilds, no false positive


# --- the byte channel of propose -------------------------------------------------------------------------------------

def capa_sources(bench, *, with_bytes: bool = True) -> cd.Sources:
    world = rf.capa_world(bench)
    imports = PeImports({side: bench.build('capa-api', side).overview for side in rf.SIDES})
    caps = CapaCapabilities(world.delta, evidence=world.evidence,
                            apis={side: capa_api_names(world.raw[side]) for side in rf.SIDES}, imports=imports)
    return cd.Sources(capabilities=caps, imports=imports, bytes=bytes_source(bench) if with_bytes else None)


def propose_capa(bench, which: str, **kw):
    check = rf.engine_checker({side: bench.build('capa-api', side).data for side in rf.SIDES})
    return cd.propose(rf.capa_pair(bench, which), capa_sources(bench), check=check, **kw)


@pytest.mark.parametrize('which,direction,numbers,pin', [
    ('term', 'older', (0x104d, 24, 20, 15, ('rip-disp',)), 'TerminateProcess'),
    ('log', 'newer', (0x1096, 38, 30, 14, ('rip-disp',)), 'WriteFile'),
    ('env', 'newer', (0x1030, 35, 23, 8, ('rip-disp',)), 'GetEnvironmentVariableA')], ids=['term', 'log', 'env'])
def test_the_windows_of_the_capa_pairs_are_the_measured_ones(bench, engine, which, direction, numbers, pin):
    (candidate,) = propose_capa(bench, which).candidates
    (window,) = [f for f in candidate.features if isinstance(f, BytesFeature)]
    assert candidate.direction == direction and window.included
    assert (window.window_rva, window.length, window.literal, window.longest_run, window.mask) == numbers
    assert [(p.dll, p.name) for p in window.pins] == [('KERNEL32.dll', pin)]
    assert (window.source_hits, window.other_hits, window.separation) == (1, 0, f'{direction}-only')
    assert (candidate.engine.decoder, candidate.engine.decoder_version) == ('iced-x86', 'standin')
    states = {g.gate_id: (g.state, g.measured) for g in candidate.gates}
    assert states['len'] == ('pass', numbers[2]) and states['uniq'] == ('pass', 1) and states['sep'] == ('pass', 0)
    assert states['wild'][0] == 'pass' and states['compile'] == ('pass', 0)
    assert f'$b = {{ {window.pattern} }}' in candidate.rule_text and candidate.lineage_id != cd.lineage_id(
        candidate.source, direction, cd.FILE_LEVEL_ANCHOR)


def test_short_window_rejected_with_reason(bench, engine):
    proposal = propose_capa(bench, 'log')
    assert [c.direction for c in proposal.candidates] == ['newer']
    older = [r for r in proposal.rejected if r.direction == 'older']
    assert [(r.reason, r.gate.gate_id if r.gate else None) for r in older] == [('gate', 'len'), ('no-feature', None)]
    assert proposal.first_failure() is None                    # a candidate exists; the older rule's reason is kept
    only_older = propose_capa(bench, 'log', directions=('older',))
    assert only_older.candidates == () and only_older.first_failure() == 'Long enough: 3 literal bytes, longest run 3'
    assert {c.channel: c.coverage for c in only_older.coverage}['bytes'] == cd.Coverage('complete', 'unavailable')


def test_cosmetic_pair_yields_no_candidates(bench, engine):
    older, newer = bench.build('capa-control', 'older'), bench.build('capa-control', 'newer')
    tool = bytes_source(bench, 'capa-control')
    for old_rva, new_rva, size in ((0x1000, 0x1040, 48), (0x1030, 0x1070, 29), (0x104d, 0x108d, 24), (0x1065, 0x10a5, 38)):
        pair = rf.pair_source(older, newer, category='modified', older_function=rf.function(old_rva, size),
                              newer_function=rf.function(new_rva, size), match_id=f'cosmetic-{old_rva:x}')
        for direction in rf.SIDES:
            result = tool.windows(pair, direction)
            assert (result.windows, result.failures) == ((), ()), (old_rva, direction)
        proposal = cd.propose(pair, cd.Sources(bytes=tool),
                              check=rf.engine_checker({'older': older.data, 'newer': newer.data}))
        assert proposal.candidates == () and [r.reason for r in proposal.rejected] == ['no-feature'] * 2


def test_a_leaf_function_without_pdata_gives_pt_rule_mask_and_the_other_channels_still_speak(bench, engine):
    pair = rf.capa_pair(bench, 'term')
    leaf = pair.model_copy(update={'older': FunctionRef(rva=0x104d, extent='unknown')})
    check = rf.engine_checker({side: bench.build('capa-api', side).data for side in rf.SIDES})
    proposal = cd.propose(leaf, capa_sources(bench), check=check)
    (refusal,) = proposal.rejected
    assert (refusal.direction, refusal.reason, refusal.detail) == ('older', 'bytes-unavailable', 'PT-RULE-MASK no-extent')
    (candidate,) = proposal.candidates       # import and capability only: no byte window
    assert not any(isinstance(f, BytesFeature) for f in candidate.features) and candidate.engine.decoder == 'none'
    with pytest.raises(RuleError) as caught:
        bytes_source(bench).windows(leaf, 'older')
    assert (caught.value.code, caught.value.reason) == ('PT-RULE-MASK', 'no-extent')
    assert {c.channel: c.coverage for c in proposal.coverage}['bytes'] == cd.Coverage('unavailable', 'unavailable')


def test_packed_and_protected_builds_get_no_byte_windows(bench, engine):
    for flag in ('packed', 'protected'):
        proposal = propose_capa(bench, 'term', flags=(flag,))
        (refusal,) = proposal.rejected
        assert (refusal.reason, refusal.detail) == ('bytes-unavailable', 'the build is packed or protected')
        assert not any(isinstance(f, BytesFeature) for f in proposal.candidates[0].features)
    toolchain = propose_capa(bench, 'term', flags=('toolchain-changed',))   # a banner, not a block
    assert toolchain.rejected == () and any(isinstance(f, BytesFeature) for f in toolchain.candidates[0].features)


class FakeBytes:
    """A `BytesSource` that has windows for the older build, refuses the newer one and reports a failure it should not."""

    def __init__(self, window):
        self.window = window

    def windows(self, pair, direction):
        if direction == 'newer':
            raise RuleError('PT-RULE-DECODE', 'bytes the decoder cannot read', reason='invalid-instruction')
        failure = gates.long_enough(3, 3)
        return WindowSet((self.window,), (failure,), frozenset(), ('iced-x86', 'standin'))


def test_coverage_of_the_byte_channel_is_per_build_and_failures_beside_windows_are_not_reported(bench, engine):
    pair = rf.capa_pair(bench, 'log')
    (window,) = bytes_source(bench).windows(rf.capa_pair(bench, 'term'), 'older').windows
    proposal = cd.propose(pair, cd.Sources(bytes=FakeBytes(window)),
                          check=passing_check((window.window_rva,)))
    assert {c.channel: c.coverage for c in proposal.coverage}['bytes'] == cd.Coverage('complete', 'unavailable')
    assert [(r.direction, r.reason, r.detail) for r in proposal.rejected] == [
        ('newer', 'bytes-unavailable', 'PT-RULE-DECODE invalid-instruction'), ('newer', 'no-feature', '')]
    assert [c.direction for c in proposal.candidates] == ['older']             # no gate rejection for the older window


def test_a_stale_build_stops_the_proposal_it_is_not_a_missing_channel(bench, engine):
    pair = rf.capa_pair(bench, 'term')
    swapped = {'older': rf.tables_of(bench, 'capa-api')['newer'], 'newer': rf.tables_of(bench, 'capa-api')['older']}
    tool = BytesWindows(rf.SubsetDecoder(), swapped)
    with pytest.raises(RuleError) as caught:
        cd.propose(pair, cd.Sources(bytes=tool), check=lambda *a: None)
    assert caught.value.code == 'PT-RULE-STALE'


def passing_check(rvas: tuple[int, ...]):
    def check(name, text, pair, direction):
        own = CellResult(state='hit', hits=len(rvas), offsets=tuple(range(1, len(rvas) + 1)), rvas=rvas)
        return PairCheck(EngineStamp(version='1.21.0', version_source='pin'), LintResult(name=name, ok=True), own,
                         CellResult(state='no-hit', hits=0))
    return check


def test_strings_the_changed_code_reads_are_xref_linked_and_ticked_beside_a_window(bench):
    newer = bench.build('capa-api', 'newer')
    observed = [StringObservation(side='newer', value_sha256=hashlib.sha256(text).hexdigest(), data=text,
                                  encoding='ascii', offset=newer.data.index(text + b'\0'), evidence_run_id='r-newer',
                                  linked_by='file-level', separation='newer-only')
                for text in (b'PATCHTRACE_SYNTHETIC', b'synthetic')]
    sources = cd.Sources(strings=rf.FakeStrings(observed), bytes=bytes_source(bench))
    pair = rf.capa_pair(bench, 'env')                    # env reads PATCHTRACE_SYNTHETIC (a lea) and not `synthetic`
    (candidate,) = cd.propose(pair, sources, check=passing_check((0x1030,)),
                              directions=('newer',)).candidates
    ticks = {f.text: (f.linked_by, f.included) for f in candidate.features if isinstance(f, StringFeature)}
    assert ticks == {'PATCHTRACE_SYNTHETIC': ('xref', True), 'synthetic': ('file-level', False)}


def test_the_strings_of_the_floss_pair_are_xref_linked_to_main(bench, engine):
    delta = rf.floss_delta(bench)
    strings = FlossStrings(delta, {side: bench.build('floss-static', side).reader for side in rf.SIDES})
    sources = cd.Sources(strings=strings, bytes=bytes_source(bench, 'floss-static'))
    check = rf.engine_checker({side: bench.build('floss-static', side).data for side in rf.SIDES})
    proposal = cd.propose(rf.strings_pair(bench), sources, check=check)
    assert {c.direction: [(f.linked_by, f.included) for f in c.features] for c in proposal.candidates} == {
        'older': [('xref', True)], 'newer': [('xref', True)]}          # main is a pure rebuild: no window, the strings anchor
    assert not any(isinstance(f, BytesFeature) for c in proposal.candidates for f in c.features)
    assert proposal.coverage[-1] == cd.ChannelCoverage('bytes', cd.Coverage('complete', 'complete'))


def test_at_most_three_windows_become_three_candidates_with_their_own_lineages():
    removed = fake_pair(ref(0x1000, 280), None, 'removed')
    proposal = cd.propose(removed, cd.Sources(bytes=tool_for(body(*range(1, 41)), body(*range(100, 110)))),
                          check=passing_check((0x1000, 0x107e, 0x10fc)), directions=('older',))
    assert [c.rule_name for c in proposal.candidates] == [f'PT_{c.lineage_id[:12]}_older' for c in proposal.candidates]
    assert len({c.lineage_id for c in proposal.candidates}) == 3 == len({c.candidate_id for c in proposal.candidates})
    assert [f.window_rva for c in proposal.candidates for f in c.features if isinstance(f, BytesFeature)] == [
        0x1000, 0x107e, 0x10fc]


def test_a_real_pdata_entry_gives_the_extent_and_a_conflicting_one_is_stale(tmp_path):
    older, reader, _ = pe_image(tmp_path, text=body(1, 2, 3, 4, 5, 6, 7), pdata=runtime_function(0x1000, 0x1031))
    newer, newer_reader, _ = pe_image(tmp_path, text=body(1, 2, 0x99, 4, 5, 6, 7), name='n.dll',
                                      pdata=runtime_function(0x1000, 0x1031))
    with reader, newer_reader:
        assert older.function_extent(0x1000) == 49
        tool = BytesWindows(rf.SubsetDecoder(), {'older': older, 'newer': newer})
        builds = SimpleNamespace(sha256=older.sha256), SimpleNamespace(sha256=newer.sha256)
        pair = rf.pair_source(*builds, category='modified', older_function=rf.function(0x1000, 49),
                              newer_function=rf.function(0x1000, 49))
        (window,) = tool.windows(pair, 'older').windows
        assert (window.window_rva, window.length) == (0x1007, 21)
        lying = rf.pair_source(*builds, category='modified', older_function=rf.function(0x1000, 42),
                               newer_function=rf.function(0x1000, 49))
        with pytest.raises(RuleError) as caught:
            tool.windows(lying, 'older')
        assert (caught.value.code, caught.value.reason) == ('PT-RULE-STALE', 'extent-differs')


def flip(states: list[bool]) -> list[tuple[int, int]]:
    """Positions (1-based builds) between which the rule starts or stops matching."""
    return [(i + 1, i + 2) for i, (a, b) in enumerate(zip(states, states[1:], strict=False)) if a != b]


def test_flip_between_build_2_and_3(bench, engine):
    older_rule = propose_capa(bench, 'term').candidates[0].rule_text
    newer_rule = propose_capa(bench, 'log').candidates[0].rule_text
    builds = rf.synergy_builds(bench)

    def states(rule: str, series: list[str]) -> list[bool]:
        compiled = engine.RuleSet.compile((WorkerRule(name='x', text=rule),))
        return [compiled.scan(builds[name])[0].state == 'hit' for name in series]
    three = ['V1', 'V1r', 'V2']                              # the series: two builds of the older code, then the newer
    assert states(older_rule, three) == [True, True, False] and flip(states(older_rule, three)) == [(2, 3)]
    assert states(newer_rule, three) == [False, False, True] and flip(states(newer_rule, three)) == [(2, 3)]
    four = ['V1', 'V1r', 'V1t', 'V2']                        # an extra build in between moves the flip, never hides it
    assert flip(states(older_rule, four)) == [(3, 4)] and flip(states(newer_rule, four)) == [(3, 4)]


def test_the_golden_file_is_lf_only_and_synthetic():
    raw = GOLDEN.read_bytes()
    assert b'\r' not in raw and raw.endswith(b'\n')
    golden = json.loads(raw)
    assert golden['contract'] == 'rules-synergy-matrix/1' and 'SYNTHETIC' in golden['note']
    assert re.fullmatch(r'[\x20-\x7e\n]+', raw.decode('ascii'))
