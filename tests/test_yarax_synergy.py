"""R4 synergy known answer (YRX plan s5, SYNTHETIC inputs): bytes, masks and call pins separate what exact bytes,
masked bytes and imports alone cannot. Rules are written here as plain text; the generator is a later slice."""
from __future__ import annotations

import dataclasses
import hashlib
import json
from pathlib import Path

import pytest
from rules_fixtures import both_image, capa_layout, imp_image, la_image
from test_intel_tools_pe import capa_control_pair, diec_toolchain_pair, floss_decode_pair, floss_static_pair
from test_yarax_masks import Builds, counter, masked

from patchtrace import optional_deps
from patchtrace.yarax import engine, window
from patchtrace.yarax.contracts import CallPin, CellResult, RuleText, WorkerTarget
from patchtrace.yarax.limits import LIMITS

pytestmark = pytest.mark.skipif(optional_deps.iced_x86 is None or optional_deps.yara_x is None,
                                reason='the rules extra (yara-x, iced-x86) is not installed')
GRID = json.loads((Path(__file__).parent / 'fixtures' / 'rules' / 'synergy-matrix.json').read_text(encoding='utf-8'))
SECTION = 'pe.sections[pe.section_index(@b[i])]'
LABELS = ['exact bytes', 'masked bytes', 'import only', 'masked + import', 'masked + call-target pin']
NAME = {label: f'PT_{i:012x}_older' for i, label in enumerate(LABELS, 1)}
OLDER_RULE, NEWER_RULE = NAME['masked + call-target pin'], 'PT_000000000006_newer'
SERIES = ['V1', 'V1r', 'V1t', 'V2']


def pin_condition(pin: CallPin) -> str:
    """The call at match `i` goes through the IAT slot of `pin.name`: slot RVA = end of call + int32 displacement."""
    target = (f'{SECTION}.virtual_address + @b[i] - {SECTION}.raw_data_offset + {pin.end_offset}'
              f' + int32(@b[i] + {pin.disp_offset})')
    return (f'for any i in (1..8) : (i <= #b and for any m in pe.import_details : (m.library_name == "{pin.dll}" '
            f'and for any f in m.functions : (f.name == "{pin.name}" and f.rva == {target})))')


def rule_text(name: str, *, pattern: str | None = None, imports: tuple[tuple[str, str], ...] = (),
              pins: tuple[CallPin, ...] = ()) -> str:
    clauses = ['uint16(0) == 0x5A4D', *[f'pe.imports("{dll}", "{fn}")' for dll, fn in imports]]
    clauses += [pin_condition(pin) for pin in pins]
    strings = f'  strings:\n    $b = {{ {pattern} }}\n' if pattern else ''
    clauses += ['$b'] if pattern else []
    return f'import "pe"\nrule {name} {{\n{strings}  condition:\n    ' + '\n    and '.join(clauses) + '\n}\n'


@pytest.fixture(scope='module')
def world(tmp_path_factory):
    builds = Builds(tmp_path_factory.mktemp('rules-synergy'))
    older, newer = capa_layout(False), capa_layout(True)
    images = {'V1': older.image, 'V1r': capa_control_pair()[1], 'V1t': diec_toolchain_pair()[1], 'V2': newer.image,
              'LA': la_image(), 'IMP': imp_image(), 'BOTH': both_image()}
    images.update({f'clean{i}': data for i, data in enumerate([*floss_static_pair(), *floss_decode_pair()])})
    targets = []
    for name, data in images.items():
        sha = builds.add(data)
        targets.append(WorkerTarget(target_id=name, path=str(builds.paths[sha]), sha256=sha, size=len(data)))
    return builds, older, newer, targets


def scan(rules: dict[str, str], targets) -> dict[str, dict[str, CellResult]]:
    """Cells by rule name then target id; `rules` maps rule name to text."""
    texts = [RuleText(name=name, text=text) for name, text in rules.items()]
    out: dict[str, dict[str, CellResult]] = {}
    for cell in engine.scan(texts, targets, dataclasses.asdict(LIMITS)):
        out.setdefault(cell.rule_name, {})[cell.target_id] = cell
    return out


def term_window(world) -> window.Window:
    builds, older, newer, _ = world
    found = window.propose_windows(masked(builds, older, 'term'), None, counter(older.image), counter(newer.image))
    return found.windows[0]


def older_rules(world) -> dict[str, str]:
    builds, older, _, _ = world
    best = term_window(world)
    with builds.open(hashlib.sha256(older.image).hexdigest()) as view:
        exact = ' '.join(f'{b:02X}' for b in view.read_rva(best.rva, best.length))
    iat = (('KERNEL32.dll', 'TerminateProcess'),)
    return {
        NAME['exact bytes']: rule_text(NAME['exact bytes'], pattern=exact),
        NAME['masked bytes']: rule_text(NAME['masked bytes'], pattern=best.pattern),
        NAME['import only']: rule_text(NAME['import only'], imports=iat),
        NAME['masked + import']: rule_text(NAME['masked + import'], pattern=best.pattern, imports=iat),
        OLDER_RULE: rule_text(OLDER_RULE, pattern=best.pattern, pins=best.pins),
    }


def hits(cells: dict[str, CellResult], column: str) -> int:
    members = [f'clean{i}' for i in range(4)] if column == 'clean' else [column]
    assert {cells[m].state for m in members} <= {'hit', 'no-hit'}, f'a cell in {column} was not scanned'
    return sum(cells[m].hits for m in members)


def test_combined_rule_beats_each_channel_alone(world):
    grid = scan(older_rules(world), world[3])
    measured = {label: [min(hits(grid[NAME[label]], c), 1) for c in GRID['columns']] for label in LABELS}
    assert measured == GRID['rows']


def test_masks_make_rebuild_stable(world):
    grid = scan(older_rules(world), world[3])
    exact, masked_rule = grid[NAME['exact bytes']], grid[NAME['masked bytes']]
    assert (exact['V1r'].state, masked_rule['V1r'].state) == ('no-hit', 'hit')
    assert masked_rule['V1'].rvas == masked_rule['V1t'].rvas == (0x104D,)
    assert masked_rule['V1r'].rvas == (0x104D + 0x40,)


def test_call_pin_removes_conjunction_false_positive(world):
    grid = scan(older_rules(world), world[3])
    conjunction, pinned = grid[NAME['masked + import']], grid[OLDER_RULE]
    assert conjunction['BOTH'].state == 'hit', 'shape in one function, import used in another'
    assert pinned['BOTH'].state == pinned['LA'].state == 'no-hit'
    assert [pinned[t].state for t in ('V1', 'V1r', 'V1t')] == ['hit'] * 3


def test_flip_between_last_older_and_first_newer_build(world):
    builds, older, newer, targets = world
    new_log = masked(builds, newer, 'log')
    found = window.propose_windows(new_log, masked(builds, older, 'log'), counter(newer.image), counter(older.image))
    newer_window = found.windows[0]
    grid = scan({OLDER_RULE: older_rules(world)[OLDER_RULE],
                 NEWER_RULE: rule_text(NEWER_RULE, pattern=newer_window.pattern, pins=newer_window.pins)}, targets)
    assert [grid[OLDER_RULE][t].state for t in SERIES] == ['hit', 'hit', 'hit', 'no-hit']
    assert [grid[NEWER_RULE][t].state for t in SERIES] == ['no-hit', 'no-hit', 'no-hit', 'hit']
    assert [t.target_id for t in targets if grid[NEWER_RULE][t.target_id].state == 'hit'] == ['V2']


def test_added_function_window_hits_only_the_newer_build(world):
    builds, older, newer, targets = world
    env = masked(builds, newer, 'env')
    best = window.propose_windows(env, None, counter(newer.image), counter(older.image)).windows[0]
    grid = scan({NEWER_RULE: rule_text(NEWER_RULE, pattern=best.pattern)}, targets)[NEWER_RULE]
    assert [t.target_id for t in targets if grid[t.target_id].state == 'hit'] == ['V2']


def test_cosmetic_pair_yields_no_candidates(world):
    """The same code rebuilt with a 0x40 shift is equal after masking: nothing differs, nothing is proposed."""
    builds, older, _, _ = world
    rebuilt_image = capa_control_pair()[1]
    shifted = dataclasses.replace(older, image=rebuilt_image,
                                  functions={n: (rva + 0x40, size) for n, (rva, size) in older.functions.items()})
    for label in ('main', 'host', 'term', 'dyn'):
        source, other = masked(builds, older, label), masked(builds, shifted, label)
        assert window.changed_spans(source, other) == [], label
        found = window.propose_windows(source, other, counter(older.image), counter(rebuilt_image))
        assert found.windows == () and found.rejected == (), label


def test_unchanged_functions_of_the_api_pair_yield_no_candidates(world):
    """`main` differs between the builds only in masked call targets; host, dyn and xor are untouched."""
    builds, older, newer, _ = world
    for label in ('main', 'host', 'dyn'):
        spans = window.changed_spans(masked(builds, newer, label), masked(builds, older, label))
        assert spans == [], label


def test_fixture_images_have_not_drifted():
    """The grid is only meaningful for these exact synthetic images; a drift means regenerate the grid file."""
    assert hashlib.sha256(capa_layout(False).image + capa_layout(True).image).hexdigest() == GRID['capa_api_sha256']
