"""SPEC-31 wiring, command line: `patchtrace unified run|show|status` over a project that has ProgramIR sidecars placed.
`--no-extract` is B-00 (stored engine outputs only, whatever is placed), `--no-residual` is backup B-07, and the
read model's default view collapses the rows the IR proves unchanged (U-03). Synthetic project and sidecars; nothing
here is live evidence."""
from __future__ import annotations

import pytest
from test_unified_cli import NOTE_START, call, document, run_json
from unified_s0_fixtures import make_project
from unified_wire_support import place_pair

from patchtrace import cli


@pytest.fixture
def root(tmp_path):
    path = tmp_path / 'project'
    service = make_project(path)
    place_pair(service, scratch=tmp_path)
    service.close()
    return path


def test_run_uses_the_placed_sidecars_and_says_so(capsys, root):
    code, doc, err = run_json(capsys, root)
    assert code == 0 and doc['status'] == 'complete' and doc['result']['mode'] == 'ir'
    assert doc['warnings'][0].startswith(NOTE_START) and not [w for w in doc['warnings'] if 'extraction' in w]
    assert 'ir-not-extracted' not in doc['result']['limitations']
    assert 'unified: ladder 1/4' in err and 'unified: write 4/4' in err            # the ladder is its own stage
    assert doc['result']['counts']['decisions']['matched'] == 4


def test_no_extract_is_b00_and_no_residual_is_b07_and_every_mode_is_its_own_result(capsys, root):
    full = run_json(capsys, root)[1]['result']
    code, s0, _ = run_json(capsys, root, '--no-extract')
    assert code == 0 and s0['result']['mode'] == 's0' and 'ir-not-extracted' in s0['result']['limitations']
    assert not [w for w in s0['warnings'] if 'extraction' in w]                  # the user chose S0: no nagging
    skipped = run_json(capsys, root, '--no-residual')[1]['result']
    assert skipped['mode'] == 'ir' and len({full['result_id'], s0['result']['result_id'], skipped['result_id']}) == 3
    assert run_json(capsys, root)[1]['result']['cached'] is True                  # the full result is still stored


def test_status_reports_the_sidecars_of_the_current_result(capsys, root):
    run_json(capsys, root)
    code, out, _ = call(capsys, 'unified', 'status', root, '--json')
    ir = document(out)['result']['ir']
    assert code == 0 and ir['available'] is True and ir['older']['functions'] == ir['newer']['functions'] == 5
    assert set(ir['older']) == {'ir_key', 'functions', 'producer_mode'} and ir['older']['producer_mode'] == 'analyze'
    run_json(capsys, root, '--no-extract')                  # another result, not the one the project's plan asks for
    _, out, _ = call(capsys, 'unified', 'status', root, '--json')
    assert document(out)['result']['ir']['available'] is True


def test_show_collapses_the_rows_the_ir_proves_unchanged_and_all_lists_them(capsys, root):
    run_json(capsys, root)
    code, out, _ = call(capsys, 'unified', 'show', root, '--json', '--limit', 100)
    result = document(out)['result']
    names = [r['function'] for r in result['rows']]
    assert code == 0 and 'format_name' not in names and 'keep_same' not in names and result['hidden'] == 2
    assert names[0] == 'read_item'                                                 # material first
    _, out, _ = call(capsys, 'unified', 'show', root, '--json', '--limit', 100, '--all')
    rows = {r['function']: r for r in document(out)['result']['rows']}
    assert rows['format_name']['collapsed'] is True and rows['format_name']['proof'] == 'UNCH/1'
    cells = {c['source']: c for c in rows['read_item']['cells']}
    assert set(cells) == {'ghidriff', 'pt-ladder'} and cells['pt-ladder']['text'] == 'P03 name-exact (A)'


def test_the_help_names_the_switches(capsys):
    assert cli.main(['unified', 'run', '--help']) == 0
    text = ' '.join(capsys.readouterr().out.split())
    assert '--no-residual' in text and 'P16-P19' in text and '--no-extract' in text and '--no-decompile' in text


def test_python_and_ghidra_dir_go_together_and_no_decompile_is_a_real_switch(capsys, root):
    code, _out, err = call(capsys, 'unified', 'run', root, '--in-process', '--python', 'python')
    assert code == 2 and '--python and --ghidra-dir go together' in err
    code, doc, _ = run_json(capsys, root, '--no-decompile')
    assert code == 0 and not [x for x in doc['result']['limitations'] if 'decompile' in x]
    code, doc, _ = run_json(capsys, root, '--refresh')   # decompile on, nothing configured, no pair worth a decompile
    assert code == 0 and not [x for x in doc['result']['limitations'] if 'decompile' in x]
