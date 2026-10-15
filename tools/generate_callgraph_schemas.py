"""Regenerate the call-graph JSON Schemas and examples (WB2 G4).

Run from the repository root:

    PYTHONPATH=src python tools/generate_callgraph_schemas.py          # write
    PYTHONPATH=src python tools/generate_callgraph_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/callgraph/``: one JSON Schema per persisted-shape contract plus
``examples.json`` (valid and invalid SYNTHETIC examples; no Microsoft data). Files are written with LF on every OS.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'callgraph'
if str(ROOT / 'src') not in sys.path:  # run without PYTHONPATH=src
    sys.path.insert(0, str(ROOT / 'src'))

CONTRACTS = ('GraphNode', 'GraphEdge', 'Pairing', 'GraphView', 'CallDelta', 'GraphLead', 'ObservedPaths',
             'NeighbourhoodEvolution', 'GraphExport', 'HubRegistry')
SCHEMA_BASE = 'https://patchtrace.local/schemas/callgraph/1/'
A, B = 'a' * 64, 'b' * 64


def _models() -> dict:
    from patchtrace.callgraph import contracts, contracts_delta, contracts_evolution, export_json, noise
    modules = (contracts, contracts_delta, contracts_evolution, export_json, noise)
    return {name: next(getattr(m, name) for m in modules if hasattr(m, name)) for name in CONTRACTS}


def valid_records() -> dict:
    from patchtrace.callgraph import contracts as c
    from patchtrace.callgraph import contracts_delta as d
    from patchtrace.callgraph import contracts_evolution as e
    from patchtrace.callgraph.export_json import GraphExport
    from patchtrace.callgraph.noise import DEFAULT_HUBS
    caller = c.GraphNode(id='n-caller', side='newer', kind='function', label='FUN_140001640', via='emitted-record',
                         tier='record', function_id='f-1', match_id='m-1', address=0x140001640)
    callee = c.GraphNode(id='n-callee', side='newer', kind='external', label='ntoskrnl.exe::ProbeForRead',
                         via='external', tier='record', flags=('import',))
    edge = c.GraphEdge(id='e-1', src=caller.id, dst=callee.id, side='newer', support=('called',))
    pairing = c.Pairing(kind='one', partners=('FUN_140001500',), via='ghidriff:Symbols',
                        engines=(c.Opinion(via='ghidriff:Symbols', partners=('FUN_140001500',)),))
    view = c.GraphView(project_id='p-1', run_id='r-1', older_sha256=A, newer_sha256=B, side='newer',
                       nodes=(caller, callee), edges=(edge,), completeness='changed-set-lists',
                       limitations=('Direct calls only.',),
                       source=c.SourceInfo(source_id='ghidriff-lists', version='1', tier='labels'))
    change = d.CalleeChange(cls='added-call', newer_label=callee.label, newer_node=callee.id, pairing=pairing,
                            flags=('import', 'newly-imported'),
                            api=(d.ApiHit(api='ProbeForRead', rule_id='R-BOUNDS', rule_revision='1', family='bounds',
                                          via='rule-hint'),))
    delta = d.CallDelta(match_id='m-1', newer_label=caller.label, state='compared', changes=(change,),
                        limitations=('only distinct callees are compared',))
    signal = d.GraphSignal(id='import-called', rank=3, meaning='Newly calls the import ProbeForRead',
                           next_step='Read the call site and the arguments.',
                           evidence=d.ClaimRef(record_id='f-1', field='callees'))
    lead = d.GraphLead(match_id='m-1', signals=(signal,), origin=d.Origin(engine='ghidriff-lists', run_id='r-1',
                                                                          raw_sha256=B),
                       blast=d.Blast(direct_callers=1, observed_callers=2, unknown_frontier=1),
                       entry=d.EntryDistance(state='reached', hops=2, via='DriverEntry'))
    paths = d.ObservedPaths(side='newer', paths=((caller.id, callee.id),), labels={caller.id: caller.label,
                                                                                    callee.id: callee.label},
                            truncated=False, completeness='changed-set-lists',
                            note='Observed path of at most 1 calls; calls outside the stored lists are not seen.')
    lineage = e.CalleeLineage(id='l-1', labels_by_ordinal=('X', 'X', None), cells=('present', 'present', 'absent'),
                              events=(e.LineageEvent(kind='dropped', ordinal=2),))
    evolution = e.NeighbourhoodEvolution(series_id=A, chain_id=B, builds=('b0', 'b1', 'b2'),
                                         focus_labels=('F', 'F', 'F'), lineages=(lineage,))
    export = GraphExport(project_id='p-1', run_id='r-1', match_id='m-1', older_sha256=A, newer_sha256=B, newer=view)
    return {'GraphNode': caller, 'GraphEdge': edge, 'Pairing': pairing, 'GraphView': view, 'CallDelta': delta,
            'GraphLead': lead, 'ObservedPaths': paths, 'NeighbourhoodEvolution': evolution, 'GraphExport': export,
            'HubRegistry': DEFAULT_HUBS}


def _invalid(valid: dict) -> dict:
    node = valid['GraphNode'].model_dump(mode='json')
    view = valid['GraphView'].model_dump(mode='json')
    delta = valid['CallDelta'].model_dump(mode='json')
    lineage = valid['NeighbourhoodEvolution'].model_dump(mode='json')
    return {
        'GraphNode': [
            {'label': 'extra field', 'value': {**node, 'surprise': 1}},
            {'label': 'kind outside the vocabulary', 'value': {**node, 'kind': 'maybe'}},
            {'label': 'label over 512 characters', 'value': {**node, 'label': 'x' * 513}}],
        'GraphView': [
            {'label': 'orientation is always older to newer', 'value': {**view, 'orientation': 'newer->older'}},
            {'label': 'side outside older and newer', 'value': {**view, 'side': 'left'}}],
        'CallDelta': [
            {'label': 'change class outside the vocabulary',
             'value': {**delta, 'changes': [{**delta['changes'][0], 'cls': 'verified'}]}},
            {'label': 'negative omitted count', 'value': {**delta, 'omitted': -1}}],
        'NeighbourhoodEvolution': [
            {'label': 'cell outside present, absent, unknown',
             'value': {**lineage, 'lineages': [{**lineage['lineages'][0], 'cells': ['present', 'no', 'absent']}]}}]}


def render() -> dict[Path, str]:
    models = _models()
    out: dict[Path, str] = {}
    for name in CONTRACTS:
        schema = models[name].model_json_schema()
        schema['$id'] = f'{SCHEMA_BASE}{name}.json'
        out[OUT / f'{name}.json'] = json.dumps(schema, indent=2, sort_keys=True) + '\n'
    valid = valid_records()
    invalid = _invalid(valid)
    examples = {name: {'valid': [record.model_dump(mode='json')], 'invalid': invalid.get(name, [])}
                for name, record in valid.items()}
    out[OUT / 'examples.json'] = json.dumps(examples, indent=2, sort_keys=True) + '\n'
    return out


def main(argv: list[str]) -> int:
    rendered = render()
    if '--check' in argv:
        stale = [p for p, text in rendered.items() if not p.is_file() or p.read_text(encoding='utf-8') != text]
        for path in stale:
            print(f'stale: {path.relative_to(ROOT)}', file=sys.stderr)
        return 1 if stale else 0
    OUT.mkdir(parents=True, exist_ok=True)
    for path, text in rendered.items():
        path.write_text(text, encoding='utf-8', newline='\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
