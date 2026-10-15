"""SPEC-31 S6a corpus CLI (`python -m tools.unified.corpus`): exit codes as SPEC-32 (0 ok, 1 findings, 2 usage or contract,
3 BLOCKED), pin verification of a fetch, and the whole chain build -> A/A -> mutate -> manifest on a tiny LOCAL project
(no network, fake checkouts with receipts, real compiles; missing tools are recorded as BLOCKED)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path[:0] = [str(ROOT), str(TESTS)]
from tier_r_helpers import require  # noqa: E402

from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import fetch as FE  # noqa: E402
from tools.calibration.tier_r import toolchain as T  # noqa: E402
from tools.unified.corpus import catalogue, cli, manifest  # noqa: E402

A_V1 = 'int tp_add(int a, int b)\n{\n    return a + b * 3;\n}\nint tp_neg(int a)\n{\n    return -a;\n}\n'
A_V2 = 'int tp_add(int a, int b)\n{\n    return a + b * 5;\n}\nint tp_neg(int a)\n{\n    return -a;\n}\n'
B_V = 'unsigned tp_mix(unsigned a)\n{\n    return (a << 3) ^ (a >> 5);\n}\nint tp_two(void)\n{\n    return 2;\n}\n'
OLD, NEW = '1' * 40, '2' * 40
CARD_ID = 'tinyproj-v1-to-v2'


def make_world(tmp_path, monkeypatch):
    """A fake fetched checkout of two versions of a freestanding project, a recipe and a card for it."""
    monkeypatch.setenv('PATCHTRACE_CALIB_ROOT', str(tmp_path / 'calib'))
    store = tmp_path / 'calib' / 'known-answer'
    for commit, a in ((OLD, A_V1), (NEW, A_V2)):
        root = FE.checkout_dir(store, 'tinyproj', commit)
        root.mkdir(parents=True)
        (root / 'a.c').write_text(a, encoding='utf-8', newline='\n')
        (root / 'b.c').write_text(B_V, encoding='utf-8', newline='\n')
        (root / FE.RECEIPT).write_text(json.dumps({'commit': commit, 'verified': True, 'commit_time': 0}),
                                       encoding='utf-8')
    recipe = C.Recipe.model_validate_json(json.dumps({
        'contract': 'tier-r-recipe/1', 'project': 'tinyproj', 'family': 'synthetic',
        'upstream_git': 'https://github.com/example/tinyproj.git', 'license_spdx': 'MIT', 'license_file': 'LICENSE',
        'license_evidence': 'test fixture', 'libc': 'freestanding', 'output': 'tinyproj.dll', 'sources': ['*.c'],
        'include_dirs': ['.'], 'pins': [
            {'ref': 'v1', 'commit': OLD, 'license_sha256': '0' * 64}, {'ref': 'v2', 'commit': NEW, 'license_sha256': '0' * 64}]}))
    book = C.RecipeBook(contract='tier-r-recipes/1', recipes=(recipe,))
    card = C.load_cards(json.dumps([{
        'contract': 'case-card/1', 'id': CARD_ID, 'project': 'tinyproj', 'upstream_git': 'https://github.com/example/t.git',
        'license_spdx': 'MIT', 'license_evidence': 'test', 'old': {'ref': 'v1', 'commit': OLD},
        'new': {'ref': 'v2', 'commit': NEW}, 'kind': 'release', 'semantic_change': True}]).encode())[0]
    digests = catalogue.Digests(old=catalogue.tree_sha256(FE.checkout_dir(store, 'tinyproj', OLD)),
                                new=catalogue.tree_sha256(FE.checkout_dir(store, 'tinyproj', NEW)))
    pins = catalogue.UnifiedPins(contract='unified-corpus-pins/1', pairs={CARD_ID: digests})
    monkeypatch.setattr(catalogue, 'recipe_book', lambda: book)
    monkeypatch.setattr(catalogue, 'load_cards', lambda: (card,))
    monkeypatch.setattr(catalogue, 'load_pins', lambda: pins)
    return store, pins


def test_every_command_is_documented_in_the_help(capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main(['--help'])
    assert stop.value.code == 0
    text = capsys.readouterr().out
    for command in ('toolchain', 'check', 'fetch', 'build', 'aa', 'mutate', 'manifest'):
        assert command in text


def test_an_unknown_command_or_pair_or_class_is_a_usage_error(capsys, tmp_path, monkeypatch):
    make_world(tmp_path, monkeypatch)
    with pytest.raises(SystemExit) as stop:
        cli.main(['frobnicate'])
    assert stop.value.code == 2
    assert cli.main(['build', '--pairs', 'no-such-pair']) == 2
    assert cli.main(['mutate', '--classes', 'no-such-class']) == 2
    assert cli.main(['mutate', '--per-class', '0']) == 2
    assert 'no-such-pair' in capsys.readouterr().err


def test_check_is_clean_on_the_committed_catalogue_and_findings_exit_1(capsys, monkeypatch):
    assert cli.main(['check']) == 0 and 'ok' in capsys.readouterr().out
    monkeypatch.setattr(catalogue, 'problems', lambda: ['card x: no recipe'])
    assert cli.main(['check']) == 1 and 'card x: no recipe' in capsys.readouterr().out


def test_a_missing_toolchain_is_blocked_with_the_reason_and_never_a_pass(capsys, monkeypatch):
    empty = T.Toolchain({n: T.Tool(n, None, reason='not installed (not on PATH)') for n in T.CANDIDATES})
    monkeypatch.setattr(T, 'probe', lambda *a, **k: empty)
    assert cli.main(['toolchain']) == 3
    assert 'BLOCKED' in capsys.readouterr().out


def fake_fetch(tamper=False):
    def fetch(url, commit, dest, tools, **kw):
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)
        if tamper:
            (dest / 'extra.c').write_text('int tampered;\n', encoding='utf-8')
        return {'commit': commit, 'verified': True}
    return fetch


def test_fetch_compares_the_tree_digest_with_pins_json(tmp_path, monkeypatch, capsys):
    store, pins = make_world(tmp_path, monkeypatch)
    monkeypatch.setattr(T, 'probe', lambda *a, **k: T.Toolchain({'git': T.Tool('git', '/usr/bin/git', 'git')}))
    monkeypatch.setattr(FE, 'fetch_commit', fake_fetch())          # leaves the checkouts exactly as made
    assert cli.main(['fetch']) == 0 and 'ok' in capsys.readouterr().out
    monkeypatch.setattr(FE, 'fetch_commit', fake_fetch(tamper=True))
    assert cli.main(['fetch']) == 1
    assert 'PT-UC-PIN' in capsys.readouterr().out
    assert pins.pairs[CARD_ID].old != pins.pairs[CARD_ID].new


def test_fetch_can_print_the_digests_a_maintainer_would_pin(tmp_path, monkeypatch, capsys):
    _, pins = make_world(tmp_path, monkeypatch)
    monkeypatch.setattr(T, 'probe', lambda *a, **k: T.Toolchain({'git': T.Tool('git', '/usr/bin/git', 'git')}))
    monkeypatch.setattr(FE, 'fetch_commit', fake_fetch())
    assert cli.main(['fetch', '--print-digests']) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed == {'contract': 'unified-corpus-pins/1', 'pairs': json.loads(pins.model_dump_json())['pairs']}


def test_a_pair_that_was_never_fetched_says_so_and_exits_1(tmp_path, monkeypatch, capsys, record_live_status):
    require(record_live_status, 'msvc-free')
    make_world(tmp_path, monkeypatch)
    for commit in (OLD, NEW):
        (FE.checkout_dir(tmp_path / 'calib' / 'known-answer', 'tinyproj', commit) / FE.RECEIPT).unlink()
    assert cli.main(['build']) == 1
    assert 'fetch' in capsys.readouterr().err


def test_the_chain_build_aa_mutate_manifest_on_a_local_project(tmp_path, monkeypatch, capsys, record_live_status):
    require(record_live_status, 'msvc-free')
    store, _ = make_world(tmp_path, monkeypatch)
    assert cli.main(['build']) == 0
    assert cli.main(['aa', '--projects', 'tinyproj']) == 0
    assert cli.main(['mutate', '--classes', 'constant,callee-swap,buf-resize', '--per-class', '2']) == 0
    out = tmp_path / 'manifest.json'
    assert cli.main(['manifest', '--out', str(out)]) == 0
    built = manifest.load(out.read_bytes())
    by_role = {}
    for pair in built.pairs:
        by_role.setdefault(pair.role, []).append(pair)
    assert set(by_role) >= {'release', 'P0', 'P1', 'mutation'}
    assert [p.x_vs_x for p in by_role['P0']] == [True]               # the reproducible rebuild is X versus X
    assert {p.mutation.unified_class for p in by_role['mutation']} == {'constant', 'callee-swap', 'buf-resize'}
    assert len(by_role['mutation']) == 6
    assert (store / 'labels').is_dir() and len(list((store / 'labels').glob('*.json'))) == len(built.pairs)
    assert 'twice' not in capsys.readouterr().err


def test_a_label_document_edited_after_generation_stops_the_manifest(tmp_path, monkeypatch, capsys, record_live_status):
    require(record_live_status, 'msvc-free')
    store, _ = make_world(tmp_path, monkeypatch)
    assert cli.main(['build']) == 0
    victim = next((store / 'labels').glob('*.json'))
    text = victim.read_text(encoding='utf-8')
    assert '"notes": ""' in text
    victim.write_text(text.replace('"notes": ""', '"notes": "edited"', 1), encoding='utf-8')
    assert cli.main(['manifest', '--out', str(tmp_path / 'm.json')]) == 2
    assert 'digest' in capsys.readouterr().err
