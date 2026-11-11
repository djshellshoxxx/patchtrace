"""Status slice ST: tools/status/build_status.py regenerates docs/status/* from the committed inventories.

Hermetic: stdlib only, no network, no clock. The inventories are analyst data, so the shape checks tolerate extra
keys and unexpected values (reported as `nonconforming`, bounded here) but fail on a missing required key."""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import unicodedata
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / 'tools' / 'status' / 'build_status.py'
STATUS = ROOT / 'docs' / 'status'
INVENTORIES = sorted((STATUS / 'inventory').glob('*.json'))
NONCONFORMING_BOUND = 60

_spec = importlib.util.spec_from_file_location('build_status', TOOL)
tool = importlib.util.module_from_spec(_spec)
sys.modules['build_status'] = tool
_spec.loader.exec_module(tool)


def run(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(TOOL), '--root', str(root), *args],
                          capture_output=True, text=True, encoding='utf-8', check=False)


@pytest.fixture()
def tree(tmp_path: Path) -> Path:
    shutil.copytree(STATUS, tmp_path / 'docs' / 'status', ignore=shutil.ignore_patterns('*.md'))
    return tmp_path


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding='utf-8'))


def test_there_are_inventories():
    assert INVENTORIES, 'docs/status/inventory/*.json is empty'


def test_regenerate_and_compare(tree):
    assert run(tree).returncode == 0
    for name in tool.GENERATED:
        assert (tree / 'docs' / 'status' / name).read_bytes() == (STATUS / name).read_bytes(), name


def test_generation_is_deterministic(tree):
    run(tree)
    first = {n: (tree / 'docs' / 'status' / n).read_bytes() for n in tool.GENERATED}
    run(tree)
    assert first == {n: (tree / 'docs' / 'status' / n).read_bytes() for n in tool.GENERATED}


def test_committed_status_files_are_lf_utf8_with_trailing_newline():
    for path in [*INVENTORIES, STATUS / 'meta.json', STATUS / 'slices.json', *(STATUS / n for n in tool.GENERATED)]:
        raw = path.read_bytes()
        raw.decode('utf-8')
        assert b'\r' not in raw and raw.endswith(b'\n'), path.name


def test_no_machine_local_paths_in_status_files():
    for path in STATUS.rglob('*'):
        if path.is_file():
            assert '/tmp/claude' not in path.read_text(encoding='utf-8'), path.name


@pytest.mark.parametrize('path', INVENTORIES, ids=[p.stem for p in INVENTORIES])
def test_inventory_shape(path):
    data = load(path)
    assert data['workstream'] == path.stem
    fatal, nonconforming = tool.validate(path.stem, data)
    assert fatal == []
    print(f'{path.stem}: {len(nonconforming)} nonconforming', *nonconforming[:5], sep='\n  ')
    assert len(nonconforming) <= NONCONFORMING_BOUND


def test_every_percentage_is_within_range_and_odd_values_are_reported():
    for path in INVENTORIES:
        data = load(path)
        nonconforming = '\n'.join(tool.validate(path.stem, data)[1])
        pcts = [(f['id'], k, f.get(k)) for f in data['features'] for k in ('implementation_pct', 'validation_pct')]
        pcts += [(path.stem, k, data.get('completion', {}).get(k)) for k in ('implementation_pct', 'validation_pct')
                 if k in data.get('completion', {})]
        for ident, key, value in pcts:
            assert isinstance(value, (int, float)) and not isinstance(value, bool), (ident, key)
            assert 0 <= value <= 100, (ident, key, value)
        for feature in data['features']:
            for field, allowed in (('status', tool.STATUSES), ('evidence_class', tool.EVIDENCE_CLASSES)):
                if feature[field] not in allowed:
                    assert repr(feature[field]) in nonconforming, (feature['id'], field)
            for defect in feature.get('defects', []):
                if defect.get('severity') not in tool.SEVERITIES:
                    assert repr(defect.get('severity')) in nonconforming, feature['id']


@pytest.mark.parametrize('drop', ['workstream', 'title', 'features', 'actionable_now'])
def test_missing_required_key_is_fatal(tree, drop):
    path = tree / 'docs' / 'status' / 'inventory' / 'B.json'
    data = load(path)
    del data[drop]
    path.write_text(json.dumps(data), encoding='utf-8')
    done = run(tree)
    assert done.returncode == 2
    assert 'B.json' in done.stderr and drop in done.stderr


def test_missing_feature_key_is_fatal(tree):
    path = tree / 'docs' / 'status' / 'inventory' / 'B.json'
    data = load(path)
    del data['features'][0]['status']
    path.write_text(json.dumps(data), encoding='utf-8')
    done = run(tree)
    assert done.returncode == 2 and 'status' in done.stderr


def test_malformed_json_is_exit_two_with_file_and_reason(tree):
    (tree / 'docs' / 'status' / 'inventory' / 'B.json').write_text('{"workstream": ', encoding='utf-8')
    done = run(tree)
    assert done.returncode == 2 and 'B.json' in done.stderr


def test_unknown_extra_keys_are_preserved_not_fatal(tree):
    path = tree / 'docs' / 'status' / 'inventory' / 'B.json'
    data = load(path)
    data['brand_new_key'] = {'x': 1}
    data['features'][0]['another_new_key'] = [1]
    path.write_text(json.dumps(data), encoding='utf-8')
    assert run(tree).returncode == 0


def test_bad_arguments_are_exit_two(tree):
    assert run(tree, '--as-of', '11-11-2026').returncode == 2
    assert run(tree, '--no-such-flag').returncode == 2


def test_as_of_argument_overrides_meta(tree):
    assert run(tree, '--as-of', '2030-01-02').returncode == 0
    assert load(tree / 'docs' / 'status' / 'status.json')['as_of'] == '2030-01-02'


BLENDED = re.compile(r'overall|blended|average|weighted|combined|project_completion|total_completion', re.I)


def walk_keys(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from walk_keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from walk_keys(item)


def test_status_json_has_no_blended_completion_percentage():
    status = load(STATUS / 'status.json')
    assert not [k for k in walk_keys(status) if BLENDED.search(k)]
    top = set(status)
    assert not top & {'completion', 'implementation_pct', 'validation_pct', 'pct', 'percent'}
    measures = status['completion_measures']
    assert measures and all(m['basis'] for m in measures)
    assert len({m['measure'] + m['workstream'] for m in measures}) == len(measures)


def test_status_json_sums_match_workstreams():
    status = load(STATUS / 'status.json')
    for field in ('features_by_status', 'defects_by_severity', 'blockers_by_type'):
        for key, total in status['totals'][field].items():
            assert total == sum(w[field].get(key, 0) for w in status['workstreams'].values()), (field, key)
    assert status['totals']['effort_hours_not_implemented'] == pytest.approx(
        sum(w['effort_hours_not_implemented'] for w in status['workstreams'].values()))


def test_missing_workstreams_are_listed_not_zero(tree):
    for path in (tree / 'docs' / 'status' / 'inventory').glob('*.json'):
        if path.stem != 'B':
            path.unlink()
    assert run(tree).returncode == 0
    status = load(tree / 'docs' / 'status' / 'status.json')
    assert set(status['workstreams']) == {'B'}
    assert status['not_inventoried'] == ['A', 'C', 'D', 'E', 'F', 'G', 'H', 'I1', 'I2', 'I3', 'J', 'K', 'L', 'R', 'T1', 'T2']
    readme = (tree / 'docs' / 'status' / 'README.md').read_text(encoding='utf-8')
    assert 'not yet inventoried' in readme.lower() and 'A, C, D' in readme


def test_check_is_clean_on_committed_tree_and_writes_nothing(tree):
    run(tree)
    before = {p.name: p.read_bytes() for p in (tree / 'docs' / 'status').iterdir() if p.is_file()}
    done = run(tree, '--check')
    assert done.returncode == 0, done.stdout
    assert before == {p.name: p.read_bytes() for p in (tree / 'docs' / 'status').iterdir() if p.is_file()}


@pytest.mark.parametrize('name', ['README.md', 'inventory.md', 'defects.md', 'status.json'])
def test_check_exits_one_when_a_generated_file_is_altered(tree, name):
    run(tree)
    target = tree / 'docs' / 'status' / name
    target.write_bytes(target.read_bytes() + b'x\n')
    altered = target.read_bytes()
    done = run(tree, '--check')
    assert done.returncode == 1 and name in done.stdout
    assert target.read_bytes() == altered


def test_check_exits_one_when_a_generated_file_is_missing(tree):
    run(tree)
    (tree / 'docs' / 'status' / 'defects.md').unlink()
    done = run(tree, '--check')
    assert done.returncode == 1 and 'defects.md' in done.stdout
    assert not (tree / 'docs' / 'status' / 'defects.md').exists()


HOSTILE = 'evil | pipe\nnew line `tick ‮ rtl \x07 bell <b>x</b> [l](http://x) \\'


def table_problems(lines: list[str]) -> list[str]:
    """Rows whose count of unescaped pipes differs from their table's header."""
    bad, width = [], 0
    for line in lines:
        if not line.startswith('|'):
            width = 0
            continue
        cells = len(re.split(r'(?<!\\)\|', line))
        if line.startswith('| ---'):
            continue
        width = width or cells
        if cells != width:
            bad.append(line)
    return bad


def test_hostile_values_cannot_break_tables_or_survive_as_control_characters(tree):
    path = tree / 'docs' / 'status' / 'inventory' / 'B.json'
    data = load(path)
    feature = data['features'][0]
    data['title'] = HOSTILE
    data['completion'] = {'implementation_pct': 50, 'validation_pct': 20, 'basis': HOSTILE}
    feature['name'] = HOSTILE
    feature['remaining'] = [HOSTILE, HOSTILE, HOSTILE]
    feature['defects'] = [{'id': HOSTILE, 'severity': 'high', 'summary': HOSTILE, 'evidence': HOSTILE,
                           'failure_scenario': HOSTILE, 'proposed_fix': HOSTILE, 'regression_test': HOSTILE}]
    feature['blockers'] = [{'type': 'external-tool', 'detail': HOSTILE}]
    path.write_text(json.dumps(data), encoding='utf-8')
    assert run(tree).returncode == 0
    for name in ('README.md', 'inventory.md', 'defects.md'):
        text = (tree / 'docs' / 'status' / name).read_text(encoding='utf-8')
        assert 'evil' in text, name
        assert table_problems(text.split('\n')) == [], name
        assert all(unicodedata.category(c) not in {'Cc', 'Cf', 'Cs', 'Zl', 'Zp'} for c in text.replace('\n', ''))
        assert '<b>' not in text and '[l](' not in text
    status = (tree / 'docs' / 'status' / 'status.json').read_bytes()
    assert status.isascii() and b'\\u202e' in status


def test_table_checker_detects_a_broken_row():
    assert table_problems(['| a | b |', '| --- | --- |', '| x | y | z |'])


def test_a_defect_listed_on_two_features_is_counted_once(tree):
    path = tree / 'docs' / 'status' / 'inventory' / 'B.json'
    data = load(path)
    defect = {'id': 'DUP-1', 'severity': 'high', 'summary': 's', 'evidence': 'e'}
    data['features'][0]['defects'] = [defect]
    data['features'][1]['defects'] = [defect]
    for f in data['features'][2:]:
        f['defects'] = []
    path.write_text(json.dumps(data), encoding='utf-8')
    run(tree)
    after = load(tree / 'docs' / 'status' / 'status.json')['workstreams']['B']['defects_by_severity']
    assert after['high'] == 1
