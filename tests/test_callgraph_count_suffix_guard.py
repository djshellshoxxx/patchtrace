"""Issue #105 BUG-CG-2: untrusted count suffixes cannot abort the actual normalized call graph."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from callgraph_graph_support import graph_input

from patchtrace.callgraph import labels
from patchtrace.callgraph import snapshot as snapshot_module


@pytest.mark.parametrize('label,expected', [
    ('ReadBuffer-0', ('ReadBuffer', 0)),
    ('ReadBuffer-0003', ('ReadBuffer', 3)),
    ('ReadBuffer-9999999999', ('ReadBuffer', 9999999999)),
    ('ReadBuffer-' + '9' * 200, ('ReadBuffer', 10**200 - 1)),
    ('a-b-12', ('a-b', 12)),
    ('ReadBuffer-\u0663', None),
    ('ReadBuffer-\uff13', None),
    ('ReadBuffer-3\n', None),
    ('ReadBuffer-3\r\n', None),
    ('ReadBuffer-3 ', None),
    ('ReadBuffer-+3', None),
    ('Read\nBuffer-3', None),
    ('-3', None),
], ids=['zero', 'leading-zeroes', 'ten-digits', 'large-accepted-count', 'dashed-stem', 'arabic-digit',
        'fullwidth-digit', 'newline', 'crlf', 'space', 'plus', 'multiline-stem', 'missing-stem'])
def test_suffix_boundaries_preserve_accepted_integer_semantics(label, expected):
    assert labels.split_count_suffix(label) == expected


def test_guarded_counts_preserve_raw_text_and_exact_precedence_through_real_ingestion():
    # Isolated, explicitly pinned guard; never mutate the test runner's or the application's process policy.
    script = r'''
import copy
import sys
from callgraph_graph_support import project_and_raw, reader_for
from patchtrace.callgraph.project_input import read_project_input
from patchtrace.callgraph.resolver import Resolver
from patchtrace.callgraph.snapshot import build_snapshot

assert sys.get_int_max_str_digits() == 4300
large = 'ReadBuffer-' + '9' * 5000
other = large[:-1] + '8'
for field in ('called', 'calling'):
    def mutate(raw):
        raw['functions']['modified'][0]['new'][field] = [large, other]
    project, raw = project_and_raw('count_suffix', mutate)
    before = copy.deepcopy(raw)
    dispatch = next(f for m in project.matches for f in m.newer if f.name == 'Dispatch')
    assert getattr(dispatch, 'callees' if field == 'called' else 'callers') == [large, other]
    data = read_project_input(project, None, reader_for(raw))
    snap = build_snapshot(data)
    graph = snap.newer
    nodes = [graph.nodes[graph.raw_labels.index(text)] for text in (large, other)]
    assert all(node.kind == 'label-only' and node.via == 'unresolved' for node in nodes)
    assert all(node.function_id is None and 'inferred-count-suffix' not in node.flags for node in nodes)
    assert nodes[0].label == nodes[1].label and nodes[0].id != nodes[1].id
    stem = Resolver(data, 'newer').resolve('ReadBuffer')
    assert all(node.id != stem.id for node in nodes)
    origin = graph.raw_labels.index('Dispatch')
    for text in (large, other):
        target = graph.raw_labels.index(text)
        edge = (origin, target) if field == 'called' else (target, origin)
        assert edge in graph.support
    assert raw == before
    assert getattr(dispatch, 'callees' if field == 'called' else 'callers') == [large, other]

# A genuine exact record with an arbitrary numeric-looking name must still win before suffix inference.
def exact(raw):
    record = raw['functions']['modified'][2]['new']
    record['name'] = record['fullname'] = large
    raw['functions']['modified'][0]['new']['called'] = [large]
project, raw = project_and_raw('count_suffix', exact)
data = read_project_input(project, None, reader_for(raw))
snap = build_snapshot(data)
node = snap.newer.nodes[snap.newer.raw_labels.index(large)]
record = next(f for m in project.matches for f in m.newer if f.name == large)
assert node.kind == 'function' and node.via == 'emitted-record' and node.function_id == record.id
assert node.flags == ()
print('guarded caller/callee snapshots preserve raw identity and exact-record precedence')
'''
    repo = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    search_paths = [str(repo / 'tests'), str(repo / 'src'), str(repo)]
    if env.get('PYTHONPATH'):
        search_paths.append(env['PYTHONPATH'])
    env['PYTHONPATH'] = os.pathsep.join(search_paths)
    result = subprocess.run([sys.executable, '-X', 'int_max_str_digits=4300', '-c', script],
                            capture_output=True, text=True, timeout=15, env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    assert 'preserve raw identity and exact-record precedence' in result.stdout


def test_suffix_policy_invalidates_prior_derived_snapshot_keys(monkeypatch):
    data = graph_input('count_suffix')
    current = snapshot_module.snapshot_key(data)
    monkeypatch.setattr(snapshot_module, 'ALGO', 'callgraph/1')
    assert snapshot_module.snapshot_key(data) != current
