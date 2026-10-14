"""Parity harness (tools/unified/parity.py; SPEC-31 08 s4, G-U3, amendment A-15). SYNTHETIC data and a FAKE bindiff:
nothing here is evidence about a real BinDiff or Ghidriff run (live parity stays BLOCKED until a pin exists)."""
from __future__ import annotations

import gzip
import json
import sqlite3
import sys
import threading
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS)]
from fake_exe import make_fake_exe  # noqa: E402
from unified_ir_builder import generate_pair  # noqa: E402

from patchtrace.secondary.bindiff_run import FORBIDDEN_FLAGS, build_argv  # noqa: E402
from patchtrace.unified import keys  # noqa: E402
from patchtrace.unified.contracts import Atom, SideRef, Support, UnifiedMatch  # noqa: E402
from patchtrace.unified.ladder.engine import run_ladder, run_ladder_data  # noqa: E402
from patchtrace.unified.ladder.side import SideData  # noqa: E402
from tools.unified import parity  # noqa: E402

SHA_A, SHA_B = 'a' * 64, 'b' * 64


def lp(older, newer, step='P04-bytes-exact', tier='A', cls='E-BODY', source='pt-bytes'):
    return parity.LadderPair(older, newer, step, tier, cls, source)


def row(older, newer, steps=('P04-bytes-exact',)):
    atoms = tuple(Atom(source='pt-bytes', step=s, tier='A', cardinality='1:1', cls='E-BODY', older_rva=older,
                       newer_rva=newer) for s in steps)
    return UnifiedMatch(row_id=keys.row_id(SHA_A, SHA_B, [older], [newer]), older=(SideRef(rva=older, kind='function'),),
                        newer=(SideRef(rva=newer, kind='function'),), decision='matched',
                        support=(Support(component='K2', tier='A', atom_index=0),), atoms=atoms)


# ---- ladder side ---------------------------------------------------------------------------------------------------------------

def test_ladder_from_correspondence_skips_anchors_and_names_steps():
    from unified_ir_builder import SyntheticIr
    older, newer = SyntheticIr(), SyntheticIr()
    for ir in (older, newer):
        ir.add('a', seed=1)
        ir.add('b', seed=2)
    corr = run_ladder(older, newer, anchors=[(0, 0)])
    pairs = parity.ladder_from_correspondence(corr)
    assert [(p.older, p.newer, p.step, p.tier, p.source) for p in pairs] == [
        (older.rva_of('b'), newer.rva_of('b'), 'P04-bytes-exact', 'A', 'pt-bytes')]


def test_ladder_from_rows_reads_ladder_atoms_of_one_to_one_rows_only():
    manual = UnifiedMatch(
        row_id=keys.row_id(SHA_A, SHA_B, [1, 2], [3]), older=(SideRef(rva=1, kind='function'), SideRef(rva=2, kind='function')),
        newer=(SideRef(rva=3, kind='function'),), decision='ambiguous', atoms=(
            Atom(source='pt-bytes', step='P04-bytes-exact', tier='A', cardinality='1:1', cls='E-BODY', older_rva=1,
                 newer_rva=3),))
    rows = [row(10, 20, ('P05-masked-exact', 'P08-mnemonic-seq')), manual, row(11, 21).model_dump(mode='json')]
    pairs = parity.ladder_from_rows(rows)
    assert [(p.older, p.newer, p.step) for p in pairs] == [(10, 20, 'P05-masked-exact'), (10, 20, 'P08-mnemonic-seq'),
                                                           (11, 21, 'P04-bytes-exact')]


# ---- oracles --------------------------------------------------------------------------------------------------------------------------

def test_read_ghidriff_address_matches_and_modified():
    raw = {'matches': {'address_matches': {
        '140001000': [['140002000', ['SymbolsHash', 'ExactBytesFunctionHasher']]],
        '140001100': [['140002100', ['ExactBytesFunctionHasher']], ['140002200', ['StructuralGraphHash']]],
        'EXTERNAL:0000000c': [['EXTERNAL:0000000d', ['ExternalsName']]],
        '140001300': [['EXTERNAL:0000000e', ['ExternalsName']]],
        '1000': [['140002400', ['SymbolsHash']]],                              # below the image base
        'zz': [['1', []]]}},
        'functions': {'modified': [
            {'old': {'address': '140001000'}, 'new': {'address': '140002000'}, 'diff_type': ['code', 'refcount'],
             'match_types': ['SymbolsHash']},
            {'old': {'address': '999'}, 'new': {'address': None}, 'match_types': []}]}}
    oracle = parity.read_ghidriff(raw, older_base=0x140000000, newer_base=0x140000000)
    got = {(p.older, p.newer): (p.label, p.extra) for p in oracle.pairs}
    assert got[(0x1000, 0x2000)] == ('SymbolsHash', 'modified:code,refcount')             # `modified` is the richer record
    assert got[(0x1100, 0x2100)][0] == 'ExactBytesFunctionHasher' and (0x1100, 0x2200) in got
    assert oracle.dropped['external-key'] == 2 and oracle.dropped['unparsable-address'] == 1
    assert oracle.dropped['modified-without-address'] == 1
    assert oracle.dropped['address-outside-image'] == 1


def test_read_bindiff_subtracts_base_and_counts_outside_image():
    oracle = parity.read_bindiff([(0x140001000, 0x140002000, 'hash matching'), (0x5, 0x6, 'name hash matching')],
                                 0x140000000, 0x140000000)
    assert [(p.older, p.newer, p.label) for p in oracle.pairs] == [(0x1000, 0x2000, 'hash matching')]
    assert oracle.dropped['address-outside-image'] == 2


# ---- comparison ------------------------------------------------------------------------------------------------------------------------

def test_compare_oracle_counts_agreement_contradiction_and_absence():
    ladder = [lp(1, 10), lp(2, 20), lp(3, 30), lp(4, 40, step='P10-md-flowgraph', tier='B', cls='E-CFG',
                                                   source='pt-ladder')]
    oracle = parity.Oracle('ghidriff', [parity.OraclePair(1, 10, 'SymbolsHash'), parity.OraclePair(2, 99, 'ExactBytes'),
                                        parity.OraclePair(5, 50, 'ExactBytes'), parity.OraclePair(6, 60, 'SymbolsHash')],
                           parity.Counter())
    report = parity.compare_oracle(ladder, oracle)
    p04 = report['steps']['P04-bytes-exact']
    assert (p04['pairs'], p04['agree'], p04['disagree'], p04['absent']) == (3, 1, 1, 1)
    (disagreement,) = p04['disagreements']
    assert disagreement == {'older': 2, 'newer': 20, 'ladder': {'step': 'P04-bytes-exact', 'tier': 'A', 'cls': 'E-BODY',
                                                                'source': 'pt-bytes'},
                            'oracle': [{'newer': 99, 'label': 'ExactBytes', 'extra': ''}]}
    assert report['steps']['P10-md-flowgraph']['absent'] == 1
    assert report['not_reproduced_total'] == 3
    assert report['not_reproduced']['ExactBytes']['paired_differently'] == 1             # older 2 is paired, differently
    assert report['not_reproduced']['ExactBytes']['unmatched'] == 1
    assert report['not_reproduced']['SymbolsHash']['unmatched'] == 1


def test_disagreement_listing_is_capped_and_counted():
    ladder = [lp(i, i + 1000) for i in range(parity.MAX_LISTED + 25)]
    oracle = parity.Oracle('bindiff', [parity.OraclePair(i, i + 5000, 'hash') for i in range(parity.MAX_LISTED + 25)],
                           parity.Counter())
    step = parity.compare_oracle(ladder, oracle)['steps']['P04-bytes-exact']
    assert step['disagree'] == parity.MAX_LISTED + 25
    assert len(step['disagreements']) == parity.MAX_LISTED and step['disagreements_truncated'] == 25


# ---- MD index --------------------------------------------------------------------------------------------------------------------------

def test_md_dump_parser_accepts_address_decimal_lines_and_counts_the_rest():
    text = '\n'.join(['00401000   0.277559753196', '0x401010: 1.000000000000', 'garbage line', 'Call graph MD: 12', '',
                       '00401020\t-0.5'])
    values, unparsed = parity.parse_md_dump(text)
    assert values == {0x401000: '0.277559753196', 0x401010: '1.000000000000', 0x401020: '-0.5'}
    assert unparsed == 2


def test_md_key_uses_decimal_arithmetic_not_float():
    assert parity.md_key_of('0.277559753195558') == 277559753196
    assert parity.md_key_of('0.000000000000500') == 0           # half to even: 0.5 units of 1e-12 -> 0
    assert parity.md_key_of('0.000000000001500') == 2
    assert parity.md_key_of('not a number') is None


def test_compare_md_histogram():
    ir = {0x1000: 277559753196, 0x1010: 5, 0x1020: 100, 0x1030: None, 0x1040: 7}
    dump = {0x401000: '0.277559753196', 0x401010: '0.000000000006', 0x401020: '0.000000000900', 0x401030: '1.5',
            0x401050: '2.0'}
    hist = parity.compare_md(ir, dump, image_base=0x400000)
    assert (hist['exact'], hist['differs_1e-12'], hist['differs']) == (1, 1, 1)
    assert hist['missing_in_dump'] == 1 and hist['missing_in_ir'] == 2          # 0x1040 absent from the dump
    assert hist['compared'] == 3 and hist['exact_per_mille'] == 333
    assert hist['differing_samples'] == [{'rva': 0x1020, 'ir_key': 100, 'dump_key': 900}]


def test_read_ir_md_reads_the_frozen_fn_table(tmp_path):
    path = tmp_path / 'ir.sqlite3'
    db = sqlite3.connect(path)
    db.execute('CREATE TABLE fn (fid INTEGER PRIMARY KEY, rva INTEGER NOT NULL UNIQUE, md_td INTEGER, md_bu INTEGER)')
    db.executemany('INSERT INTO fn VALUES (?,?,?,?)', [(0, 0x1000, 11, 12), (1, 0x1100, None, 13)])
    db.commit()
    db.close()
    assert parity.read_ir_md(path) == {0x1000: 11, 0x1100: None}


# ---- report ------------------------------------------------------------------------------------------------------------------------------

def test_report_is_deterministic_and_the_digest_excludes_itself():
    ladder = [lp(1, 10), lp(2, 20)]
    oracle = parity.Oracle('ghidriff', [parity.OraclePair(1, 10, 'SymbolsHash')], parity.Counter())
    one = parity.build_report(ladder, [oracle], meta={'tool': 't'})
    two = parity.build_report(list(reversed(ladder)), [oracle], meta={'tool': 't'})
    assert parity.canonical(one) == parity.canonical(two)
    assert one['report_sha256'] == parity.report_digest(one) and len(one['report_sha256']) == 64
    assert one['ladder']['by_step'] == {'P04-bytes-exact': 2}
    tampered = dict(one, ladder={'pairs': 99, 'by_step': {}, 'by_tier': {}})
    assert parity.report_digest(tampered) != one['report_sha256']
    assert '\r' not in parity.canonical(one)


def test_ladder_output_against_a_truth_shaped_oracle_has_no_contradiction():
    """End to end on the generator: the ladder's pairs checked against the generator's ground truth, written in the
    Ghidriff address_matches shape (virtual addresses)."""
    pair = generate_pair(600, seed=5)
    base = 0x140000000
    raw = {'matches': {'address_matches': {f'{base + o:x}': [[f'{base + n:x}', ['SymbolsHash']]]
                                           for o, n in pair.truth.items()}}}
    corr = run_ladder_data(SideData.from_ir(pair.older), SideData.from_ir(pair.newer))
    report = parity.build_report(parity.ladder_from_correspondence(corr), [parity.read_ghidriff(raw, base, base)])
    steps = report['oracles']['ghidriff']['steps']
    assert steps and all(s['disagree'] == 0 and s['absent'] == 0 for s in steps.values())
    assert sum(s['agree'] for s in steps.values()) == len(corr.pairs)
    assert report['oracles']['ghidriff']['not_reproduced_total'] == len(pair.truth) - len(corr.pairs)


# ---- the dev-only md_index argv (A-15) ---------------------------------------------------------------------------------------------

def test_md_dump_argv_is_dev_only_and_product_argv_still_forbids_md_index(tmp_path):
    argv = parity.md_dump_argv('/opt/bindiff/bin/bindiff', '/tmp/x/primary.BinExport')
    assert argv == ['/opt/bindiff/bin/bindiff', '--nologo', '--md_index', '--primary=/tmp/x/primary.BinExport']
    assert '--md_index' in FORBIDDEN_FLAGS
    assert '--md_index' not in build_argv('/opt/bindiff/bin/bindiff', tmp_path)
    src_hits = [p for p in (ROOT / 'src').rglob('*.py') if '--md_index' in p.read_text(encoding='utf-8')
                and 'FORBIDDEN_FLAGS' not in p.read_text(encoding='utf-8')
                and p.name not in {'binexport_check.py', 'binexport_limits.py', 'binexport_prescan.py', 'mdindex.py'}]  # mdindex: docstring
    assert src_hits == []           # no product module builds an --md_index argv


FAKE_BINDIFF = r'''
import json, os, sys
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spy.jsonl'), 'a', encoding='utf-8') as spy:
    spy.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(), 'env_keys': sorted(os.environ)}) + '\n')
primary = [a for a in sys.argv[1:] if a.startswith('--primary=')][0].split('=', 1)[1]
assert os.path.isfile(primary) and os.path.basename(primary) == 'primary.BinExport'
print('00401000   0.277559753196')
print('00401010   1.000000000000')
'''


def test_run_md_dump_with_a_fake_bindiff(tmp_path):
    """FAKE executable (mocked evidence): argv, private cwd, copied input, allow-listed environment, stdout."""
    exe = make_fake_exe(tmp_path / 'bin', 'bindiff', FAKE_BINDIFF)
    source = tmp_path / 'user named it.BinExport'
    source.write_bytes(b'not a real binexport')
    result = parity.run_md_dump(exe, source, timeout=60)
    assert result['exit'] == 0
    values, unparsed = parity.parse_md_dump(result['stdout'])
    assert values == {0x401000: '0.277559753196', 0x401010: '1.000000000000'} and unparsed == 0
    spy = json.loads((tmp_path / 'bin' / 'spy.jsonl').read_text(encoding='utf-8').splitlines()[0])
    assert spy['argv'][:2] == ['--nologo', '--md_index'] and spy['argv'][2].startswith('--primary=')
    assert 'user named it' not in spy['argv'][2]                    # the user's file name never reaches argv
    assert Path(spy['cwd']).name.startswith('pt-md-')               # private working directory
    assert not {'PYTHONPATH', 'HTTPS_PROXY', 'GITHUB_TOKEN'} & set(spy['env_keys'])
    assert result['input_sha256'] == __import__('hashlib').sha256(b'not a real binexport').hexdigest()
    assert not Path(spy['cwd']).exists()                            # removed afterwards


def test_run_md_dump_refuses_a_relative_executable(tmp_path):
    with pytest.raises(ValueError):
        parity.run_md_dump(Path('bindiff'), tmp_path / 'x.BinExport', cancel=threading.Event())


# ---- CLI ---------------------------------------------------------------------------------------------------------------------------------

def test_cli_report_writes_deterministic_lf_json(tmp_path, capsys):
    rows = tmp_path / 'rows.jsonl.gz'
    with gzip.open(rows, 'wt', encoding='utf-8', newline='\n') as handle:
        for item in (row(0x1000, 0x2000), row(0x1100, 0x2100, ('P05-masked-exact',))):
            handle.write(json.dumps(item.model_dump(mode='json'), sort_keys=True) + '\n')
    raw = tmp_path / 'raw.json'
    raw.write_text(json.dumps({'matches': {'address_matches': {'140001000': [['140002000', ['SymbolsHash']]]}}}),
                   encoding='utf-8')
    out_one, out_two = tmp_path / 'one.json', tmp_path / 'two.json'
    common = ['report', '--rows', str(rows), '--ghidriff-raw', str(raw), '--older-image-base', '0x140000000',
              '--newer-image-base', '0x140000000']
    assert parity.main([*common, '--out', str(out_one)]) == 0
    assert parity.main([*common, '--out', str(out_two)]) == 0
    assert out_one.read_bytes() == out_two.read_bytes() and b'\r' not in out_one.read_bytes()
    report = json.loads(out_one.read_text(encoding='utf-8'))
    assert report['contract'] == 'parity-report/1'
    assert report['oracles']['ghidriff']['steps']['P04-bytes-exact']['agree'] == 1
    assert capsys.readouterr().out.split()[0] == report['report_sha256']
