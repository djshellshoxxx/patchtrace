"""Synthetic Ghidriff-shaped PDiff fixtures for the WB2 call-graph tracks (slice G0).

Every label, address and hash is invented: no Microsoft binary, PDB or Winbindex label. Each raw dict is
read by normalize_ghidriff; the `matches` section is not read there, so its shape (name_matches and
address_matches as label maps) is the only part the live Ghidriff gate must still confirm.

Regenerate the committed JSON with: python tests/callgraph_fixtures.py
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from patchtrace.models import AnalysisRun, Artifact, ComparisonProject

OLDER_SHA256 = hashlib.sha256(b'callgraph-fixture older').hexdigest()
NEWER_SHA256 = hashlib.sha256(b'callgraph-fixture newer').hexdigest()
SYNTHETIC_CREDIT = 'SYNTHETIC call-graph fixture; not output from Ghidriff or a real build'
FIXTURE_DIR = Path(__file__).resolve().parent / 'fixtures' / 'callgraph'


def _record(name: str, address: str | None, calling=(), called=(), code: str | None = None,
            external: bool = False) -> dict:
    return {'name': name, 'fullname': name, 'address': address, 'code': code,
            'calling': list(calling), 'called': list(called), 'sym_type': 'EXTERNAL' if external else 'FUNCTION',
            'external': external}


def _external(name: str, address: str, calling=()) -> dict:
    return _record(name, f'EXTERNAL:{address}', calling=calling, external=True)


def _modified(old: dict, new: dict, diff_types=('called',), ratio: float = 0.5) -> dict:
    return {'old': old, 'new': new, 'diff_type': list(diff_types), 'ratio': ratio,
            'match_types': ['Symbols']}


def _raw(added=(), deleted=(), modified=(), matches: dict | None = None) -> dict:
    raw = {'old_meta': {'Executable SHA256': OLDER_SHA256, 'Synthetic sample': True},
           'new_meta': {'Executable SHA256': NEWER_SHA256, 'Synthetic sample': True},
           'functions': {'added': list(added), 'deleted': list(deleted), 'modified': list(modified)},
           'md_credits': SYNTHETIC_CREDIT}
    if matches is not None:
        raw['matches'] = matches
    return raw


def _svc_pair() -> dict:
    # Known answer of WB2 section 5: D/F/P/L/H renumbered, DriverEntry named, N new, two imports added.
    old = {
        'DriverEntry': _record('DriverEntry', '140001000', called=['FUN_140001500']),
        'D': _record('FUN_140001500', '140001500', calling=['DriverEntry'],
                     called=['FUN_140001800', 'FUN_140001600', 'FUN_140001c00', 'FUN_140001200']),
        'F': _record('FUN_140001600', '140001600', calling=['FUN_140001500'], called=['FUN_140001200'],
                     code='int FormatLine(int v) {\n    return v == 1;\n}'),
        'P': _record('FUN_140001800', '140001800', calling=['FUN_140001500'],
                     called=['FUN_140001200', 'ntoskrnl.exe::ExAllocatePool2']),
        'L': _record('FUN_140001c00', '140001c00', calling=['FUN_140001500'], called=['ntoskrnl.exe::EtwWrite']),
    }
    new = {
        'DriverEntry': _record('DriverEntry', '140001000', called=['FUN_140001640']),
        'D': _record('FUN_140001640', '140001640', calling=['DriverEntry'],
                     called=['FUN_1400018c0', 'FUN_140001740', 'FUN_140001d40', 'FUN_140001340']),
        'F': _record('FUN_140001740', '140001740', calling=['FUN_140001640'], called=['FUN_140001340'],
                     code='int FormatLine(int v) {\n    return v == 2;\n}'),
        'P': _record('FUN_1400018c0', '1400018c0', calling=['FUN_140001640'],
                     called=['FUN_140001340', 'ntoskrnl.exe::ExAllocatePool2', 'ntoskrnl.exe::ProbeForRead',
                             'FUN_140001f00']),
        'L': _record('FUN_140001d40', '140001d40', calling=['FUN_140001640'],
                     called=['ntoskrnl.exe::EtwWrite', 'ntoskrnl.exe::EtwWriteTransfer']),
    }
    added = [
        _record('FUN_140001f00', '140001f00', calling=['FUN_1400018c0'], code='int CheckLength(int n) {\n    return n;\n}'),
        _external('ntoskrnl.exe::ProbeForRead', '3f0010', calling=['FUN_1400018c0']),
        _external('ntoskrnl.exe::EtwWriteTransfer', '3f0020', calling=['FUN_140001d40']),
    ]
    modified = [_modified(old[key], new[key], diff_types=('code', 'called') if key == 'F' else ('called',))
                for key in ('DriverEntry', 'D', 'F', 'P', 'L')]
    matches = {
        'name_matches': {
            'DriverEntry': 'DriverEntry',
            'FUN_140001500': 'FUN_140001640', 'FUN_140001600': 'FUN_140001740',
            'FUN_140001800': 'FUN_1400018c0', 'FUN_140001c00': 'FUN_140001d40',
            'FUN_140001200': 'FUN_140001340',
            'ntoskrnl.exe::ExAllocatePool2': 'ntoskrnl.exe::ExAllocatePool2',
            'ntoskrnl.exe::EtwWrite': 'ntoskrnl.exe::EtwWrite',
        },
        'address_matches': {
            '140001000': '140001000', '140001500': '140001640', '140001600': '140001740',
            '140001800': '1400018c0', '140001c00': '140001d40', '140001200': '140001340',
        },
    }
    return _raw(added=added, modified=modified, matches=matches)


HOSTILE_LABELS = [
    'Parse‮Record',
    'Quote"Back\\slash',
    'Esc\\N\\G\\n\\l',
    'Line\nBreak\rCarriage',
    'Ctl\x01\x7fDelete',
    'Sep Para Sep',
    'Long' + 'x' * 600,
    '<img src=x onerror=alert(1)>',
    '..\\..\\evil.dll::Run',
    'Nul\x00Byte',
]


def _hostile_names() -> dict:
    dispatch_old = _record('Dispatch', '140002000', called=HOSTILE_LABELS)
    dispatch_new = _record('Dispatch', '140002100', called=HOSTILE_LABELS + ['ntoskrnl.exe::Pwn"));DROP'])
    modified = [_modified(dispatch_old, dispatch_new)]
    for index, label in enumerate(HOSTILE_LABELS):
        address = f'{0x140003000 + index * 0x100:x}'
        old = _record(label, address, calling=['Dispatch'], code=f'void f{index}(void) {{ return; }}')
        new = _record(label, f'{0x140004000 + index * 0x100:x}', calling=['Dispatch'],
                      code=f'void f{index}(void) {{ return; }}')
        modified.append(_modified(old, new, diff_types=('code',)))
    added = [_external('ntoskrnl.exe::Pwn"));DROP', '3f0100', calling=['Dispatch'])]
    names = {'Dispatch': 'Dispatch', **{label: label for label in HOSTILE_LABELS}}
    return _raw(added=added, modified=modified,
                matches={'name_matches': names, 'address_matches': {}})


def _ambiguous_pair() -> dict:
    dispatch = _modified(_record('Dispatch', '140005000', called=['parser.dll::Parse']),
                         _record('Dispatch', '140005100', called=['parser.dll::Parse']))
    parse = _modified(_record('parser.dll::Parse', '140005200', calling=['Dispatch']),
                      _record('parser.dll::Parse', '140005300', calling=['Dispatch']), diff_types=('code',))
    second = _record('parser.dll::Parse', '140005400', calling=['Dispatch'])
    matches = {'name_matches': {'Dispatch': 'Dispatch', 'parser.dll::Parse': 'parser.dll::Parse'},
               'address_matches': {}}
    return _raw(added=[second], modified=[dispatch, parse], matches=matches)


def _no_matches() -> dict:
    # Second known answer of WB2 section 5: sample-style pair with no `matches` section at all.
    old_read = _record('read_item', '180001000', called=[],
                       code='int read_item(const char *b, size_t len, size_t i) {\n    return b[i];\n}')
    new_read = _record('read_item', '180001080', called=['report_invalid_index'],
                       code='int read_item(const char *b, size_t len, size_t i) {\n'
                            '    if (i >= len) return report_invalid_index(i, len);\n    return b[i];\n}')
    added = [_record('report_invalid_index', '180001200', calling=['read_item'],
                     code='int report_invalid_index(size_t i, size_t len) {\n    return -1;\n}')]
    deleted = [_record('debug_dump', '180001400', code='void debug_dump(const char *t) {\n    puts(t);\n}')]
    old_version = _record('get_version', '180001600', code='int get_version(void) {\n    return 1;\n}')
    new_version = _record('get_version', '180001700', code='int get_version(void) {\n    return 2;\n}')
    modified = [_modified(old_read, new_read, diff_types=('code', 'address', 'called'), ratio=0.58),
                _modified(old_version, new_version, diff_types=('code', 'address'), ratio=0.94)]
    return _raw(added=added, deleted=deleted, modified=modified)


def _count_suffix() -> dict:
    # --use-calling-counts names: ReadBuffer-3 infers its stem; Write-2 cannot (two records named Write).
    dispatch = _modified(_record('Dispatch', '140006000', called=['ReadBuffer', 'ReadBuffer-2']),
                         _record('Dispatch', '140006100',
                                 called=['ReadBuffer', 'ReadBuffer-2', 'ReadBuffer-3', 'Write-2']))
    read_buffer = _modified(_record('ReadBuffer', '140006200', calling=['Dispatch']),
                            _record('ReadBuffer', '140006300', calling=['Dispatch']), diff_types=('code',))
    read_buffer_two = _modified(_record('ReadBuffer-2', '140006400', calling=['Dispatch']),
                                _record('ReadBuffer-2', '140006500', calling=['Dispatch']), diff_types=('code',))
    added = [_record('Write', '140006600', calling=['Dispatch']),
             _record('Write', '140006700', calling=['Dispatch'])]
    matches = {'name_matches': {'Dispatch': 'Dispatch', 'ReadBuffer': 'ReadBuffer', 'ReadBuffer-2': 'ReadBuffer-2'},
               'address_matches': {}}
    return _raw(added=added, modified=[dispatch, read_buffer, read_buffer_two], matches=matches)


def _cycle_hub() -> dict:
    # CycleA <-> CycleB form a cycle; TraceMessageHub has 66 callers (fan-in >= 64).
    callers = ['CycleA', 'CycleB'] + [f'Caller{index:03d}' for index in range(64)]
    cycle_a = _modified(_record('CycleA', '140007000', calling=['CycleB'], called=['CycleB', 'TraceMessageHub']),
                        _record('CycleA', '140007100', calling=['CycleB'], called=['CycleB', 'TraceMessageHub']),
                        diff_types=('code',))
    cycle_b = _modified(_record('CycleB', '140007200', calling=['CycleA'], called=['CycleA', 'TraceMessageHub']),
                        _record('CycleB', '140007300', calling=['CycleA'], called=['CycleA', 'TraceMessageHub']),
                        diff_types=('code',))
    hub = _modified(_record('TraceMessageHub', '140008000', calling=callers),
                    _record('TraceMessageHub', '140008100', calling=callers), diff_types=('code',))
    caller_items = [
        _modified(_record(name, f'{0x140009000 + index * 0x10:x}', called=['TraceMessageHub']),
                  _record(name, f'{0x140109000 + index * 0x10:x}', called=['TraceMessageHub']), diff_types=('code',))
        for index, name in enumerate(callers[2:])
    ]
    names = {name: name for name in ['CycleA', 'CycleB', 'TraceMessageHub', *callers[2:]]}
    return _raw(modified=[cycle_a, cycle_b, hub, *caller_items],
                matches={'name_matches': names, 'address_matches': {}})


BUILDERS = {
    'svc_pair': _svc_pair,
    'hostile_names': _hostile_names,
    'ambiguous_pair': _ambiguous_pair,
    'no_matches': _no_matches,
    'count_suffix': _count_suffix,
    'cycle_hub': _cycle_hub,
}
FIXTURE_NAMES = list(BUILDERS)


def build_fixture(name: str) -> dict:
    return BUILDERS[name]()


def dump_fixture(raw: dict) -> str:
    return json.dumps(raw, indent=2, ensure_ascii=True, allow_nan=False) + '\n'


def project_for_fixtures() -> tuple[ComparisonProject, str]:
    run = AnalysisRun(status='completed')
    project = ComparisonProject(name='callgraph fixtures', artifacts=[
        Artifact(side='older', name='older.dll', sha256=OLDER_SHA256, size=1024, relative_path='older.dll'),
        Artifact(side='newer', name='newer.dll', sha256=NEWER_SHA256, size=1024, relative_path='newer.dll'),
    ], runs=[run])
    return project, run.id


def write_fixtures(directory: Path = FIXTURE_DIR) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for name in FIXTURE_NAMES:
        (directory / f'{name}.json').write_bytes(dump_fixture(build_fixture(name)).encode('utf-8'))


if __name__ == '__main__':
    write_fixtures()
