"""SPEC-31 S1: the pure parts of tools/live_unified_check.py and static checks of .github/workflows/live-unified.yml.

The live run itself (real Ghidra) is the `live-unified` workflow; these tests keep its comparison logic, its fixture
recorder and its workflow file honest without Ghidra."""
from __future__ import annotations

import importlib.util
import json
import re
import struct
import sys
from pathlib import Path

import pytest
from pe_builder import CODE, RDATA, PeSpec, SectionSpec, build_pe
from test_unified_ir_ingest import pe_from_json

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.unified.ir.pe_tables import read_pe_tables

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github' / 'workflows' / 'live-unified.yml'
BACKEND_WORKFLOW = ROOT / '.github' / 'workflows' / 'live-backend.yml'


def load_tool():
    spec = importlib.util.spec_from_file_location('pt_live_unified_check', ROOT / 'tools' / 'live_unified_check.py')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


tool = load_tool()


def test_equivalence_classes_group_by_key_value():
    assert tool.equivalence_classes([(1, 5), (2, 5), (3, 6), (4, 7), (5, 7), (6, 7)]) == {(1, 2), (3,), (4, 5, 6)}
    assert tool.equivalence_classes([]) == set()


def test_hasher_classes_compare_the_relation_not_the_values():
    ghidra = {'1': {'bytes': 10}, '2': {'bytes': 10}, '3': {'bytes': 11}, '4': {'bytes': None}}
    same_relation = {1: {'h0': -5}, 2: {'h0': -5}, 3: {'h0': 99}, 4: {'h0': 1}}
    report = tool.compare_hasher_classes(ghidra, same_relation, 'bytes', 'h0')
    assert report['equal'] and report['functions'] == 3 and report['classes_ir'] == 2
    merged = {1: {'h0': 1}, 2: {'h0': 1}, 3: {'h0': 1}}                 # IR key merges a function Ghidra separates
    report = tool.compare_hasher_classes(ghidra, merged, 'bytes', 'h0')
    assert not report['equal'] and report['only_ghidra'] == [(3,), (1, 2)]
    assert report['only_ir'] == [(1, 2, 3)]
    split = {1: {'h0': 1}, 2: {'h0': 2}, 3: {'h0': 3}}
    assert not tool.compare_hasher_classes(ghidra, split, 'bytes', 'h0')['equal']
    unknown = tool.compare_hasher_classes(ghidra, {9: {'h0': 1}}, 'bytes', 'h0')
    assert unknown['functions'] == 0 and unknown['equal']


def results(digest_old='a' * 64, digest_new='b' * 64, sha_old='1' * 64, sha_new='2' * 64, os_name='Windows'):
    return {'os': os_name, 'sides': {'older': {'artifact_sha256': sha_old, 'content_digest': digest_old},
                                     'newer': {'artifact_sha256': sha_new, 'content_digest': digest_new}}}


def test_cross_os_comparison_requires_the_same_bytes_and_equal_digests():
    assert tool.compare_with_other(results(os_name='Linux'), results()) == []
    problems = tool.compare_with_other(results(digest_new='c' * 64, os_name='Linux'), results())
    assert len(problems) == 1 and problems[0].startswith('newer: content_digest') and 'Windows' in problems[0]
    problems = tool.compare_with_other(results(sha_old='9' * 64), results())
    assert len(problems) == 1 and 'different DLL bytes' in problems[0]
    assert tool.compare_with_other(results(), {'os': 'Windows', 'sides': {}}) == [
        'older: missing in the other results', 'newer: missing in the other results']


def test_checks_ledger_prints_and_collects_failures():
    lines = []
    checks = tool.Checks(lines.append)
    assert checks.check('A ok', True) and not checks.check('B bad', False, 'because')
    checks.info('C note', 'detail')
    assert lines == ['PASS A ok', 'FAIL B bad', '     because', 'INFO C note: detail']
    assert checks.failures == ['B bad: because']


def test_pe_json_round_trips_into_the_view_the_ingest_tests_load(tmp_path):
    pdata = struct.pack('<III', 0x1000, 0x1010, 0x2000)
    xdata = bytes([0x01, 0x04, 0x01, 0x00, 0x04, 0x42, 0x00, 0x00]) + b'\0' * 8
    spec = PeSpec(kind='dll', image_base=0x180000000, sections=[
        SectionSpec('.text', b'\x90' * 0x800, CODE), SectionSpec('.xdata', xdata, RDATA),
        SectionSpec('.pdata', pdata, RDATA)], extra_directories={3: (0x3000, len(pdata))})
    path = tmp_path / 'x.dll'
    path.write_bytes(build_pe(spec))
    with VerifiedArtifactReader.open_path(path) as reader:
        original = read_pe_tables(reader)
        document = tool.pe_json(reader, original)
    assert set(document) == {'sha256', 'image_base', 'size_of_image', 'sections', 'relocs', 'primaries', 'warnings'}
    json.dumps(document)
    out = tmp_path / 'x.pe.json'
    tool.write_json(out, document)
    assert out.read_bytes().endswith(b'}\n') and b'\r' not in out.read_bytes()
    loaded = pe_from_json(out)
    assert (loaded.image_base, loaded.size_of_image) == (original.image_base, original.size_of_image)
    assert loaded.sections == original.sections and list(loaded.relocs) == list(original.relocs)
    assert {b: (p.end, p.unwind, p.chunks) for b, p in loaded.primaries.items()} == {
        b: (p.end, p.unwind, p.chunks) for b, p in original.primaries.items()}
    assert loaded.eh == {b: original.eh_for(b) for b in original.primaries}


def test_write_json_is_deterministic_and_lf(tmp_path):
    target = tmp_path / 'p.json'
    tool.write_json(target, {'b': 1, 'a': [1, 2]}, indent=1)
    assert target.read_text(encoding='utf-8') == '{\n "a": [\n  1,\n  2\n ],\n "b": 1\n}\n'
    tool.write_json(target, {'b': 1, 'a': [1, 2]})
    assert target.read_text(encoding='utf-8') == '{"a":[1,2],"b":1}\n'


def test_arguments():
    args = tool.parse_args(['--old', 'a.dll', '--new', 'b.dll', '--ghidra-dir', 'g', '--out', 'o', '--record',
                            'dir', 'n1', 'n2', '--tag', 't', '--no-hashers'])
    assert args.record == ['dir', 'n1', 'n2'] and args.tag == 't' and args.no_hashers and not args.no_ghidriff
    with pytest.raises(SystemExit):
        tool.parse_args(['--old', 'a.dll'])


def test_hasher_child_script_compiles_and_uses_only_ghidra_hashers():
    compile(tool.HASHER_SCRIPT, 'hasher-script', 'exec')
    for name in ('ExactBytesFunctionHasher', 'ExactInstructionsFunctionHasher', 'ExactMnemonicsFunctionHasher',
                 'getCodeUnits', 'getInstructions'):
        assert name in tool.HASHER_SCRIPT
    assert 'subprocess' not in tool.HASHER_SCRIPT and 'urllib' not in tool.HASHER_SCRIPT


# --- L5: how the stored keys relate to Ghidra's hashers ------------------------------------------------------------------------
# Ghidra's ExactInstructions / ExactMnemonics hash EVERY code unit of a body, the stored h1..h3 / hm skip NOP and INT3 padding
# (03 s12.5). The first live run on MSVC-built DLLs showed it: two functions that differ only by a NOP were two Ghidra classes
# and one stored class. L5 therefore checks the exported data the way Ghidra reads it, and the stored keys by refinement.

XOR, NOP, RET, INT3 = ((b'\x31\xc0', 'ffff', 'XOR', 2), (b'\x90', 'ff', 'NOP', 0), (b'\xc3', 'ff', 'RET', 0),
                       (b'\xcc', 'ff', 'INT3', 0))
MOV_1, MOV_2 = (b'\xb8\x01\x00\x00\x00', 'ff00000000', 'MOV', 2), (b'\xb8\x02\x00\x00\x00', 'ff00000000', 'MOV', 2)


def fn_record(rva, name, parts, data=b''):
    """An extractor function line from (bytes, instruction mask, mnemonic, operand count) parts; `data` trails the body."""
    insns, offset = [], 0
    for chunk, imask, mnemonic, operands in parts:
        insns.append([offset, len(chunk), mnemonic, imask, [[0, None, [], []]] * operands, 'FALL_THROUGH'])
        offset += len(chunk)
    return {'type': 'fn', 'rva': rva, 'name': name, 'raw': (b''.join(p[0] for p in parts) + data).hex(), 'insns': insns}


def l5_records():
    return [fn_record(4096, 'a', [XOR, RET]), fn_record(4112, 'b_nop', [XOR, NOP, RET]),
            fn_record(4128, 'c_pad', [XOR, RET, INT3]), fn_record(4144, 'd_twin_of_a', [XOR, RET]),
            fn_record(4160, 'e', [MOV_1, RET]), fn_record(4176, 'f_const_differs', [MOV_2, RET]),
            fn_record(4192, 'g_data', [XOR, RET], data=b'\xde\xad')]


def l5_ghidra():
    """What Ghidra's hashers give for l5_records (values are arbitrary, only the equal/different relation counts)."""
    rows = {4096: (10, 1, 1, 0), 4112: (11, 2, 2, 0), 4128: (12, 3, 3, 0), 4144: (10, 1, 1, 0), 4160: (13, 4, 6, 0),
            4176: (14, 4, 6, 0), 4192: (15, 5, 7, 1)}
    return {str(rva): {'name': str(rva), 'bytes': b, 'insns': i, 'mnem': m, 'data': d} for rva, (b, i, m, d) in rows.items()}


def l5_stored(override=None):
    """Stored keys: NOPs and trailing INT3 padding are skipped, so a, b_nop, c_pad, d and g_data share one h3 and one hm."""
    rows = {rva: {'h0': h0, 'h3': h3, 'hm': hm} for rva, h0, h3, hm in
            ((4096, 1, 7, 9), (4112, 2, 7, 9), (4128, 3, 7, 9), (4144, 1, 7, 9), (4160, 4, 8, 10), (4176, 5, 8, 10),
             (4192, 6, 7, 9))}
    for (rva, key), value in (override or {}).items():
        rows[rva][key] = value
    return rows


def run_l5(ghidra=None, stored=None, records=None):
    lines = []
    checks = tool.Checks(emit=lines.append)
    report = tool.l5_report('older', ghidra or l5_ghidra(), stored or l5_stored(), records or l5_records(), checks)
    return checks, lines, report


def test_exported_keys_read_every_instruction_and_skip_nothing():
    keys, facts = tool.exported_keys(l5_records())
    assert sorted(keys) == [4096, 4112, 4128, 4144, 4160, 4176]               # g_data has a body byte outside its instructions
    assert keys[4096] == keys[4144] != keys[4112] != keys[4128]
    assert keys[4160]['h3x'] == keys[4176]['h3x']                             # the mask zeroes the immediate
    assert keys[4096]['hmx'] == (('XOR', 2), ('RET', 0)) and keys[4112]['hmx'][1] == ('NOP', 0)
    assert facts[4112] == {'name': 'b_nop', 'insns': 3, 'gap': 0, 'skipped': 1}
    assert facts[4128]['skipped'] == 1 and facts[4192]['gap'] == 2 and facts[4096]['skipped'] == 0
    unmasked = fn_record(1, 'n', [(b'\xb8\x01\x00\x00\x00', None, 'MOV', 2)])
    assert tool.exported_keys([unmasked])[0][1]['h3x'] == b'\xb8\x01\x00\x00\x00'   # no mask: Ghidra hashes the raw bytes
    assert tool.exported_keys([{'type': 'fn', 'rva': 2, 'raw': None}, {'type': 'footer'}]) == ({}, {})


def test_l5_passes_where_stored_keys_are_coarser_only_by_skipped_instructions():
    checks, lines, report = run_l5()
    assert checks.failures == [], checks.failures
    assert sum(line.startswith('PASS L5') for line in lines) == 6
    assert any('2 of 7 functions contain NOP or INT3 padding' in line for line in lines)
    assert report['functions'] == 7 and report['skipping'] == 2 and report['with_data'] == 1
    assert report['h3']['equal'] and report['h3']['refines'] and report['h3']['functions'] == 4
    assert report['hm']['refines'] and report['h3x']['equal'] and report['hmx']['equal']


@pytest.mark.parametrize('case, label', [
    ('split', 'h3 never separates'),                    # a stored key that separates two functions Ghidra equates
    ('merge', 'h3 never separates'),                    # ...or merges two functions without skipped instructions
    ('hm-split', 'hm never separates'),
    ('export', 'exported masked instruction bytes'),    # the exported mask does not zero what Ghidra's does
    ('count', 'exported mnemonics with operand counts'),
    ('data', 'bytes outside the exported instructions'),
    ('h0', 'h0 classes equal'),
], ids=['split', 'merge', 'hm-split', 'export', 'count', 'data', 'h0'])
def test_l5_fails_on_real_disagreements(case, label):
    ghidra, stored, records = l5_ghidra(), l5_stored(), l5_records()
    if case == 'split':
        stored = l5_stored({(4144, 'h3'): 77})
    elif case == 'merge':
        stored = l5_stored({(4160, 'h3'): 7, (4176, 'h3'): 7})
    elif case == 'hm-split':
        stored = l5_stored({(4144, 'hm'): 77})
    elif case == 'export':
        records[4]['insns'][0][3] = 'ffffffffff'
    elif case == 'count':
        records[4]['insns'][0][4] = [[0, None, [], []]]
    elif case == 'data':
        ghidra['4192']['data'] = 0
    else:
        stored = l5_stored({(4144, 'h0'): 99})
    checks, lines, _ = run_l5(ghidra, stored, records)
    assert len(checks.failures) == 1 and label in checks.failures[0], checks.failures
    assert any(line.startswith('FAIL L5') for line in lines)


def test_comparing_the_stored_keys_directly_is_what_failed_on_msvc_builds():
    """The first L5 compared stored h3 / hm classes with Ghidra's: equal only while no function has a skipped NOP."""
    direct = tool.compare_hasher_classes(l5_ghidra(), l5_stored(), 'insns', 'h3')
    assert not direct['equal'] and direct['only_ir'] == [(4096, 4112, 4128, 4144, 4192)]
    assert direct['only_ghidra'] == [(4112,), (4128,), (4192,), (4096, 4144)]
    assert run_l5()[0].failures == []


def test_l5_names_the_functions_of_a_mismatch():
    checks, lines, _ = run_l5(stored=l5_stored({(4144, 'h3'): 77}))
    assert any(line.startswith('INFO L5 older: h3 groups') and 'd_twin_of_a(insns=2,skipped=0,gap=0)' in line
               for line in lines)


# --- the workflow file ------------------------------------------------------------------------------------------------------

def workflow_lines():
    return WORKFLOW.read_text(encoding='utf-8').splitlines()


def test_workflow_has_no_tabs_and_unquoted_colon_values_outside_block_scalars():
    in_block, indent = False, 0
    for number, line in enumerate(workflow_lines(), 1):
        assert '\t' not in line, number
        if in_block:
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                in_block = False
            else:
                continue
        match = re.match(r'^(\s*)(?:- )?([A-Za-z_][\w-]*):\s*(.*)$', line)
        if not match:
            continue
        value = match.group(3)
        if value in ('|', '>', '|-', '>-'):
            in_block, indent = True, len(match.group(1)) + (2 if line.lstrip().startswith('- ') else 0)
            continue
        if value and value[0] not in '\'"[{' and (': ' in value or ' #' in value):
            pytest.fail(f'line {number}: plain scalar with ": " or " #" must be quoted: {line.strip()}')


def test_workflow_pins_the_same_ghidra_and_ghidriff_as_the_backend_workflow():
    unified = WORKFLOW.read_text(encoding='utf-8')
    backend = BACKEND_WORKFLOW.read_text(encoding='utf-8')
    digest = re.search(r'GHIDRA_SHA256: ([0-9a-f]{64})', unified).group(1)
    assert digest in backend
    assert re.search(r'GHIDRA_URL: (\S+)', unified).group(1) in backend
    commit = re.search(r'ghidriff\.git@([0-9a-f]{40})', unified).group(1)
    assert commit in backend and 'pyghidra==3.0.2' in unified


def test_workflow_is_read_only_pinned_to_known_actions_and_free_of_event_data():
    text = WORKFLOW.read_text(encoding='utf-8')
    assert re.search(r'^permissions:\n  contents: read$', text, re.M)
    for action in re.findall(r'uses: (\S+)', text):
        assert action in {'actions/checkout@v4', 'actions/setup-python@v5', 'actions/setup-java@v4',
                          'actions/upload-artifact@v4', 'actions/download-artifact@v4', 'ilammy/msvc-dev-cmd@v1'}, action
    assert '${{ github.event' not in text and 'secrets.' not in text
    assert 'java-version: \'21\'' in text and text.count('tools/live_unified_check.py') >= 4


def test_workflow_analyses_the_same_dll_bytes_on_both_operating_systems():
    text = WORKFLOW.read_text(encoding='utf-8')
    assert 'needs: windows' in text and 'live-unified-windows' in text
    assert text.count('--other-results') == 2 and 'windows/fx/' in text
    sources = re.findall(r'tests\\fixtures\\(?:unified\\)?(\w+)\.c', text)
    assert sorted(sources) == ['new', 'old', 'probe_new', 'probe_old']
    for source in ('tests/fixtures/old.c', 'tests/fixtures/new.c', 'tests/fixtures/unified/probe_old.c',
                   'tests/fixtures/unified/probe_new.c'):
        assert (ROOT / source).is_file()
    for ignored in ('.pdb', '/Zi'):
        assert ignored not in text                                    # no symbols: Ghidra must not look for a PDB


def test_l5_fails_when_no_function_was_compared_ue_b_01():
    empty_values = {str(rva): {'name': 'x', 'bytes': None, 'insns': None, 'mnem': None, 'data': 0} for rva in (4096, 4112)}
    for ghidra in ({}, empty_values):
        lines = []
        checks = tool.Checks(emit=lines.append)
        tool.l5_report('older', ghidra, l5_stored(), l5_records(), checks)
        assert checks.failures, ghidra
        assert not any(line.startswith('PASS L5') and ': h0 classes' in line for line in lines)
