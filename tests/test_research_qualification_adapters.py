from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tools.research_qualification import adapters as AD  # noqa: E402
from tools.research_qualification import scoring as SC  # noqa: E402
from tools.research_qualification.__main__ import main  # noqa: E402
from tools.research_qualification.adapters import _common as CM  # noqa: E402
from tools.research_qualification.pathguard import PathGuardError  # noqa: E402

FX = Path(__file__).resolve().parent / 'fixtures' / 'research_adapters'


@pytest.fixture
def bindiff_db(tmp_path):
    db = tmp_path / 'x.BinDiff'
    con = sqlite3.connect(db)
    con.executescript((FX / 'bindiff_schema.sql').read_text(encoding='utf-8'))
    con.commit()
    con.close()
    return db


# --- fixtures (ghidriff layout checked against package source; bindiff/rizin UNVERIFIED) -------------------------

def test_ghidriff_json_ranks_and_excludes():
    got = AD.ghidriff.parse(FX / 'ghidriff_report.json')
    assert got == ['Parser::parse_header', 'alpha', 'checksum', 'Util::old_helper', 'new_helper']
    assert 'renamed_only' not in got


def test_ghidriff_markdown_ranks_by_diff_lines():
    got = AD.ghidriff.parse((FX / 'ghidriff_report.md').read_text(encoding='utf-8'))
    assert got == ['Parser::parse_header', 'small_fix', 'Util::old_helper', 'new_helper']


def test_ghidriff_accepts_bytes_and_path_equally():
    p = FX / 'ghidriff_report.json'
    assert AD.ghidriff.parse(p) == AD.ghidriff.parse(p.read_bytes()) == AD.ghidriff.parse(p.read_text('utf-8'))


def test_bindiff(bindiff_db):
    got = AD.bindiff.parse(bindiff_db)
    assert got == ['Parser::parse_header', 'only_new_name', 'alpha', 'checksum']
    assert AD.bindiff.parse(bindiff_db.read_bytes()) == got


def test_bindiff_never_writes(bindiff_db):
    before = bindiff_db.read_bytes()
    AD.bindiff.parse(bindiff_db)
    assert bindiff_db.read_bytes() == before
    assert not list(bindiff_db.parent.glob('*-journal')) and not list(bindiff_db.parent.glob('*-wal'))


def test_rizin_text_and_json():
    assert AD.rizin.parse(FX / 'radiff2_C.txt') == ['sym.parse_header', 'sym.alpha', 'sym.checksum', 'sym.new_func']
    assert AD.rizin.parse(FX / 'radiff2_C.json') == ['sym.parse_header', 'sym.checksum', 'sym.new_func']


def test_deterministic_across_runs():
    a = AD.ghidriff.parse(FX / 'ghidriff_report.json')
    assert all(AD.ghidriff.parse(FX / 'ghidriff_report.json') == a for _ in range(3))


def test_output_feeds_score_run():
    manifest = {'cases': [{'id': 'a', 'expected': {'function': 'Parser::parse_header'}},
                          {'id': 'b', 'expected': {'function': 'x'}}]}
    res = SC.score_run(manifest, {'a': AD.ghidriff.parse(FX / 'ghidriff_report.json'), 'b': None})
    assert (res['hits'], res['top1'], res['blocked']) == (1, 1, 1)


# --- normaliser ---------------------------------------------------------------------------------------------------

@pytest.mark.parametrize('raw,want', [
    ('A::b', 'A::b'), ('ns::C::~C', 'ns::C::~C'), ('sub_401000', 'sub_401000'), ('FUN_00401000', 'FUN_00401000'),
    ('_memcpy', '_memcpy'), ('__init', '__init'), ('_foo@8', 'foo'), ('@bar@12', 'bar'), ('  spaced ', 'spaced'),
    ('operator/', 'operator/'), ('', None), ('   ', None), (None, None)])
def test_normalise(raw, want):
    assert CM.normalise_name(raw) == want


@pytest.mark.parametrize('raw', ['../../etc/passwd', '..\\..\\windows\\x', 'a/../b', 'x\x00y', 'a\nb', 'evil‮name',
                                 'n' * 600])
def test_normalise_rejects_hostile(raw):
    with pytest.raises(ValueError):
        CM.normalise_name(raw)


def test_normalise_rejects_non_text():
    with pytest.raises(ValueError):
        CM.normalise_name(5)


# --- hostile input ------------------------------------------------------------------------------------------------

TEXT_ADAPTERS = [AD.ghidriff.parse, AD.rizin.parse]


@pytest.mark.parametrize('fn', TEXT_ADAPTERS)
@pytest.mark.parametrize('bad', ['', '   \n', 'garbage', '{', '[1,2', '\x00\x01binary', b'\xff\xfe\x00\x80', b'',
                                 '{"functions": 1}', '[]', '[1]', '{"a":' * 10 + '}'])
def test_malformed_raises_valueerror(fn, bad):
    with pytest.raises(ValueError):
        fn(bad)


@pytest.mark.parametrize('fn', TEXT_ADAPTERS)
def test_huge_line_rejected(fn, monkeypatch):
    monkeypatch.setattr(CM, 'MAX_LINE_CHARS', 100)
    with pytest.raises(ValueError, match='line longer'):
        fn('# Modified\n' + 'A' * 200)


@pytest.mark.parametrize('fn', TEXT_ADAPTERS)
def test_size_cap(fn, monkeypatch):
    monkeypatch.setattr(CM, 'MAX_INPUT_BYTES', 10)
    with pytest.raises(ValueError, match='exceeds'):
        fn('x' * 11)
    with pytest.raises(ValueError, match='exceeds'):
        fn(b'x' * 11)


def test_function_count_cap(monkeypatch):
    monkeypatch.setattr(CM, 'MAX_FUNCTIONS', 2)
    doc = {'functions': {'modified': [], 'deleted': [], 'added': [{'fullname': f'f{i}'} for i in range(5)]}}
    with pytest.raises(ValueError, match='more than'):
        AD.ghidriff.parse(json.dumps(doc))


def test_deep_nesting_is_valueerror():
    with pytest.raises(ValueError):
        AD.ghidriff.parse('{"functions":' + '[' * 100000 + ']' * 100000 + '}')


def test_nan_and_out_of_range_ratio_rejected():
    def doc(ratio):
        return json.dumps({'functions': {'added': [], 'deleted': [], 'modified': [
            {'old': {'fullname': 'f'}, 'diff_type': ['code'], 'ratio': ratio}]}}).replace('"NaN"', 'NaN')
    with pytest.raises(ValueError):
        AD.ghidriff.parse(doc('NaN'))
    with pytest.raises(ValueError):
        AD.ghidriff.parse(doc(1.5))
    with pytest.raises(ValueError):
        AD.ghidriff.parse(doc(True))


def test_traversal_name_in_report_rejected():
    doc = {'functions': {'modified': [], 'deleted': [], 'added': [{'fullname': '../../etc/passwd'}]}}
    with pytest.raises(ValueError, match='traversal'):
        AD.ghidriff.parse(json.dumps(doc))
    with pytest.raises(ValueError, match='traversal'):
        AD.ghidriff.parse('# Added\n\n## ../../etc/passwd\n')


def test_no_input_is_executed(tmp_path):
    marker = tmp_path / 'pwned'
    payload = {'functions': {'modified': [], 'deleted': [], 'added': [
        {'fullname': f"__import__('os').system('touch {marker}')"}]}}
    AD.ghidriff.parse(json.dumps(payload))
    assert not marker.exists()


def test_bindiff_rejects_garbage_and_wrong_schema(tmp_path):
    with pytest.raises(ValueError, match='ambiguous'):
        AD.bindiff.parse('x.BinDiff')
    with pytest.raises(ValueError):
        AD.bindiff.parse(b'\x00\xff' * 64)
    with pytest.raises(ValueError):
        AD.bindiff.parse(b'')
    other = tmp_path / 'o.db'
    con = sqlite3.connect(other)
    con.execute('CREATE TABLE t (x)')
    con.commit()
    con.close()
    with pytest.raises(ValueError, match='function'):
        AD.bindiff.parse(other)
    trunc = tmp_path / 't.db'
    trunc.write_bytes(other.read_bytes()[:200])
    with pytest.raises(ValueError):
        AD.bindiff.parse(trunc)


def test_bindiff_bad_values(tmp_path):
    db = tmp_path / 'b.BinDiff'
    con = sqlite3.connect(db)
    con.execute('CREATE TABLE function (name1 TEXT, name2 TEXT, similarity REAL, confidence REAL)')
    con.execute("INSERT INTO function VALUES ('f','f','oops',0.5)")
    con.commit()
    con.close()
    with pytest.raises(ValueError, match='similarity'):
        AD.bindiff.parse(db)
    con = sqlite3.connect(db)
    con.execute("UPDATE function SET similarity = 0.5, name1 = '../../x'")
    con.commit()
    con.close()
    with pytest.raises(ValueError, match='traversal'):
        AD.bindiff.parse(db)


# --- path confinement ---------------------------------------------------------------------------------------------

def test_paths_are_confined(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv('TMPDIR', str(tmp_path))
    outside = Path('/etc/hostname')
    for fn in (AD.ghidriff.parse, AD.rizin.parse, AD.bindiff.parse):
        with pytest.raises(PathGuardError):
            fn(outside)
        with pytest.raises(PathGuardError):
            fn(tmp_path.joinpath(*['..'] * 12, 'etc', 'passwd'))


def test_directory_is_not_a_file(tmp_path):
    with pytest.raises(ValueError, match='regular file'):
        AD.ghidriff.parse(tmp_path)


# --- CLI ----------------------------------------------------------------------------------------------------------

def test_cli_adapters(capsys, tmp_path, monkeypatch):
    monkeypatch.setenv('RQ_ALLOWED_DIRS', str(FX))
    assert main(['adapters', 'ghidriff', str(FX / 'ghidriff_report.json'), '--case', 'c1']) == 0
    out = json.loads(capsys.readouterr().out)
    assert out['c1'][0] == 'Parser::parse_header'
    assert main(['adapters', 'rizin', str(FX / 'radiff2_C.txt')]) == 0
    assert json.loads(capsys.readouterr().out)[0] == 'sym.parse_header'


def test_cli_adapters_bad_input_exit_2(capsys, tmp_path):
    bad = tmp_path / 'bad.json'
    bad.write_text('nope', encoding='utf-8')
    assert main(['adapters', 'ghidriff', str(bad)]) == 2
    assert 'error' in capsys.readouterr().err


def test_rizin_recorded_nested_layout_and_null_sides():
    import json as _json
    from pathlib import Path as _P

    from tools.research_qualification.adapters import rizin as _rz
    text = _P('tests/fixtures/secondary/rzdiff-functions.json').read_text()
    _json.loads(text)
    out = _rz.parse(text)
    assert out[0] == 'fcn.140001008'          # the only changed pair ranks first
    assert set(out[1:]) == {'fcn.140002000', 'fcn.140003000'}  # unmatched sides are one-sided, after edits


def test_ghidriff_non_code_diff_type_not_a_change():
    import json as _json

    from tools.research_qualification.adapters import ghidriff as _g
    doc = {'functions': {'added': [], 'deleted': [], 'modified': [
        {'old': {'fullname': 'a'}, 'diff_type': ['name'], 'ratio': 0.5},
        {'old': {'fullname': 'b'}, 'diff_type': ['code'], 'ratio': 0.9}]}}
    assert _g.parse(_json.dumps(doc)) == ['b']


def test_huge_json_integer_is_a_clean_error():
    import pytest

    from tools.research_qualification.adapters._common import unit_float
    with pytest.raises(ValueError):
        unit_float(10 ** 400, 'x')


def test_rizin_real_rz_diff_091_capture():
    got = AD.rizin.parse(FX / 'real' / 'rizin-functions.json')
    assert got == ['dbg.classify']
