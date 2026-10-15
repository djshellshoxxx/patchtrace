"""Regenerate the fabric/1 artefacts (FAB-1; docs/specs/program-e/FAB-integration-plan.md s7).

Run from the repository root:

    PYTHONPATH=src python tools/generate_fabric_schemas.py          # write
    PYTHONPATH=src python tools/generate_fabric_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/fabric/``: one JSON Schema per persisted record plus
``examples.json`` (valid and invalid examples per record; every invalid one names the validator message it must
trigger). Every id and digest of a valid example is derived through ``patchtrace.fabric.ids``, so the examples certify
themselves. All data is SYNTHETIC (CVE-2099-*, made-up hashes); nothing here describes a real build. Files are written
with LF on every OS (``.gitattributes`` pins ``docs/schemas/**/*.json``).
"""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'fabric'
if str(ROOT / 'src') not in sys.path:  # run without PYTHONPATH=src
    sys.path.insert(0, str(ROOT / 'src'))

CONTRACTS = ('Ref', 'Witness', 'PairRef', 'Anchor', 'FabricBatch', 'PinEvent')
# Records stored or exchanged on their own carry a `contract` constant; the others only live inside those.
STANDALONE = {'FabricBatch': 'fabric-batch/1', 'PinEvent': 'fabric-pin/1'}


def _h(tag: str) -> str:
    return hashlib.sha256(f'fabric-example-{tag}'.encode()).hexdigest()


OLDER, NEWER = _h('older'), _h('newer')


def models() -> dict:
    from patchtrace.fabric import contracts, pins, store
    return {'Ref': contracts.Ref, 'Witness': contracts.Witness, 'PairRef': contracts.PairRef,
            'Anchor': contracts.Anchor, 'FabricBatch': store.FabricBatch, 'PinEvent': pins.PinEvent}


def valid_records() -> dict[str, list]:
    """Valid SYNTHETIC records per contract (a list each), built from the real constructors so they are valid by
    construction: ids are derived, witnesses sorted, the batch holds only its own witnesses."""
    from patchtrace.fabric import ids, origins
    from patchtrace.fabric.contracts import PairRef, Ref
    from patchtrace.fabric.pins import PinEvent
    from patchtrace.fabric.store import FabricBatch

    refs = [Ref(kind='tool-evidence', id='tool-run-1'),
            Ref(kind='advisory-facts', id='facts-1', pointer='/vulnerabilities/0/notes/1', sha256=_h('facts'))]
    pairs = [PairRef(older_sha256=OLDER, newer_sha256=NEWER, older_rvas=(0x1000, 0x1010), newer_rvas=(0x1040,)),
             PairRef(older_sha256=OLDER, newer_sha256=NEWER, older_rvas=(0x2000,), newer_rvas=())]
    pair = ids.pair_key_of(pairs[0])

    def witness(producer, batch, source, tags, label, **more):
        return ids.make_witness(producer=producer, batch=batch, source=source, origins=tags, label=label, **more)

    paired = witness('ue', 'ue1', 'pairing', ('D_ghidra',), 'ParsePacket')
    seen = witness('cap', 'cap1', 'capa', ('D_vivisect',), 'RtlULongAdd', input_sha256=NEWER, ref=refs[0],
                   facets={'name': 'RtlULongAdd', 'dll': 'ntdll'}, tool='capa', tool_version='9.0.0')
    rule = witness('cap', 'cap1', 'capa', ('D_vivisect',), 'create process', input_sha256=NEWER, ref=refs[1],
                   facets={'namespace': 'host-interaction/process/create', 'scope': 'function'})
    advised = witness('kb', 'kb1', 'advisory-text', ('D_vendor_text',), 'CWE-190 integer overflow')
    anchors = {
        'pair': ids.make_anchor(kind='function', side='both', role='observed', pair=pairs[0], witnesses=(paired,)),
        'removed': ids.make_anchor(kind='function', side='both', role='observed', pair=pairs[1], witnesses=(paired,)),
        'import': ids.make_anchor(kind='import', key=ids.api_key('RtlULongAdd'), side='newer', role='observed',
                                  subject=pair, witnesses=(seen,)),
        'capability': ids.make_anchor(kind='capability', key='create process', side='newer', role='observed',
                                      subject=pair, witnesses=(rule,)),
        'hint': ids.make_anchor(kind='import', key=ids.api_key('RtlULongAdd'), side='none', role='hint',
                                witnesses=(advised,)),
        'cwe': ids.make_anchor(kind='cwe', key='CWE-190', side='none', role='stated', witnesses=(advised,))}

    def batch(producer, name, *members):
        return FabricBatch(producer=producer, batch=name, origins_digest=origins.digest(),
                           anchors=tuple(sorted(members, key=lambda anchor: anchor.anchor_id)))

    def pin_event(**more):
        seen_anchor = anchors['import']
        fields = {'seq': 1, 'action': 'pin', 'anchor_id': seen_anchor.anchor_id, 'kind': seen_anchor.kind,
                  'key': seen_anchor.key, 'side': seen_anchor.side, 'role': seen_anchor.role,
                  'subject': seen_anchor.subject, 'label': seen_anchor.label, 'note': '', 'via': 'related',
                  'older_sha256': OLDER, 'newer_sha256': NEWER, 'created_utc': '2099-03-01T12:00:00+00:00'}
        return PinEvent(**(fields | more))

    return {
        'Ref': refs,
        'Witness': [paired, seen, rule],
        'PairRef': pairs,
        'Anchor': [anchors['pair'], anchors['import'], anchors['hint'], anchors['cwe']],
        'FabricBatch': [batch('cap', 'cap1', anchors['import'], anchors['capability']),
                        batch('ue', 'ue1', anchors['pair'], anchors['removed'])],
        'PinEvent': [pin_event(note='Check the overflow guard.\nThen the caller.'),
                     pin_event(seq=2, action='unpin', via='analyst', created_utc='2099-03-01T12:05:00Z')]}


def _set(path: str, value):
    """Mutator: set a dotted path (list indexes are numbers) in an example document."""
    def mutate(doc):
        node = doc
        *head, last = path.split('.')
        for part in head:
            node = node[int(part)] if isinstance(node, list) else node[part]
        node[int(last) if isinstance(node, list) else last] = value
    return mutate


def _swap(path: str, first: int, second: int):
    """Mutator: exchange two items of a list in an example document."""
    def mutate(doc):
        node = doc
        for part in path.split('.'):
            node = node[int(part)] if isinstance(node, list) else node[part]
        node[first], node[second] = node[second], node[first]
    return mutate


# record -> (index of the valid example it mutates, mutator, reason, substring the validation error must contain)
SPECIFIC_INVALID = {
    'Ref': [(0, _set('kind', 'Tool Evidence'), 'a source kind is a slug', 'string_pattern_mismatch'),
            (1, _set('pointer', 'vulnerabilities/0'), 'a pointer is an RFC 6901 pointer', 'string_pattern_mismatch'),
            (1, _set('sha256', 'ABC'), 'hashes are lower-case hex', 'string_pattern_mismatch')],
    'Witness': [(0, _set('producer', 'gui'), 'producers are a closed list', 'literal_error'),
                (0, _set('origins', []), 'a witness names its origins', 'too_short'),
                (1, _set('origins', ['D_vivisect', 'D_bytes']), 'origins are sorted', 'sorted and unique'),
                (0, _set('label', 'a\nb'), 'a label is one line of plain text', 'one line of plain text'),
                (1, _set('facets', [['name', 'x'], ['dll', 'y']]), 'facets are sorted by name', 'sorted and unique'),
                (0, _set('witness_id', 'xyz'), 'ids are SHA-256 hex', 'string_pattern_mismatch')],
    'PairRef': [(0, _set('older_rvas', [4112, 4096]), 'RVAs ascend', 'sorted and unique'),
                (0, _set('newer_rvas', [2 ** 32]), 'an RVA fits 32 bits', 'less_than_equal'),
                (1, _set('older_rvas', []), 'a pair needs a function on a side', 'at least one function')],
    'Anchor': [(0, _set('kind', 'api'), 'kinds are a closed list', 'literal_error'),
               (0, _set('side', 'sideways'), 'sides are a closed list', 'literal_error'),
               (0, _set('witnesses', []), 'an anchor has a witness', 'too_short'),
               (1, _set('anchor_id', 'abc'), 'ids are SHA-256 hex', 'string_pattern_mismatch'),
               (3, _set('witnesses', [None]), 'a witness is a record', 'model_type')],
    'FabricBatch': [(0, _set('producer', 'gui'), 'producers are a closed list', 'literal_error'),
                    (0, _set('origins_digest', 'xyz'), 'the origin table is named by its digest',
                     'string_pattern_mismatch'),
                    (0, _set('anchors', []), 'a stored batch holds an anchor', 'too_short'),
                    (0, _swap('anchors', 0, 1), 'anchors are sorted by id', 'sorted and unique by anchor_id'),
                    (0, _set('batch', 'ue1'), 'a row holds the witnesses of its own batch', 'its row'),
                    (0, _set('batch', 'Cap 1'), 'a batch name is a slug', 'string_pattern_mismatch')],
    'PinEvent': [(0, _set('action', 'delete'), 'actions are pin and unpin', 'literal_error'),
                 (0, _set('seq', 0), 'a sequence number starts at 1', 'greater_than_equal'),
                 (0, _set('key', 'someotherapi'), 'the id is derived from the identity', 'must be derived'),
                 (0, _set('role', 'stated'), 'the role is one the kind allows', 'not allowed for this kind'),
                 (0, _set('note', 'a\tb'), 'a note is plain text', 'one line of plain text'),
                 (0, _set('note', 'a' * 2049), 'a note is at most 2 KiB of characters', 'too_long'),
                 (0, _set('note', '\u00e9' * 1025), 'a note is at most 2 KiB of UTF-8', 'at most 2048 bytes'),
                 (1, _set('note', 'still true'), 'an unpin carries no note', 'no note'),
                 (0, _set('via', 'Related'), 'where a pin came from is a slug', 'string_pattern_mismatch'),
                 (0, _set('created_utc', '2099-03-01 12:00:00'), 'the time is UTC ISO 8601',
                  'string_pattern_mismatch')]}


def build_examples() -> dict:
    out = {}
    for name, records in valid_records().items():
        valid = [json.loads(record.model_dump_json()) for record in records]
        invalid = [{'example': valid[0] | {'unexpected_field': 1}, 'reason': 'extra fields are forbidden',
                    'match': 'extra_forbidden'}]
        if name in STANDALONE:
            invalid.append({'example': valid[0] | {'contract': 'fabric-batch/2'},
                            'reason': 'unsupported future contract version', 'match': 'literal_error'})
        for index, mutate, reason, match in SPECIFIC_INVALID.get(name, ()):
            document = copy.deepcopy(valid[index])
            mutate(document)
            invalid.append({'example': document, 'reason': reason, 'match': match})
        out[name] = {'valid': valid, 'invalid': invalid}
    return out


def render_contract_schemas() -> dict[str, str]:
    out = {}
    for name, model in models().items():
        schema = model.model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/fabric/1/{name}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        out[f'{name}.json'] = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return out


def render() -> dict[Path, str]:
    """Every generated file and its exact text (a pure function of the repository contents)."""
    files = {OUT / name: text for name, text in render_contract_schemas().items()}
    files[OUT / 'examples.json'] = json.dumps(build_examples(), indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return files


def main(argv: list[str]) -> int:
    check = '--check' in argv
    drift = []
    for path, text in render().items():
        if check:
            current = path.read_text(encoding='utf-8') if path.is_file() else None
            if current != text:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
    for item in drift:
        print(f'stale: {item}', file=sys.stderr)
    return 1 if drift else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
