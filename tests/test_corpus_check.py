"""Validator for corpus inputs (tools/corpus_check.py): template passes, authoring mistakes are caught."""
from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('corpus_check', ROOT / 'tools' / 'corpus_check.py')
corpus_check = importlib.util.module_from_spec(spec)
spec.loader.exec_module(corpus_check)
TEMPLATE = ROOT / 'corpus' / 'ours' / '_template' / 'tiny'
needs_clang = pytest.mark.skipif(shutil.which('clang') is None, reason='BLOCKED: clang is not installed')


def good_card(**changes):
    card = {'contract': 'case-card/1', 'id': 'demo-1-to-2', 'project': 'demo', 'upstream_git': 'https://example.org/d.git',
            'license_spdx': 'MIT', 'license_evidence': 'LICENSE: MIT', 'old': {'ref': 'v1', 'commit': 'a' * 40},
            'new': {'ref': 'v2', 'commit': 'b' * 40}, 'kind': 'cve-fix', 'cve': ['CVE-2000-0001'],
            'semantic_change': True, 'changed_functions': [{'name': 'f', 'file': 'f.c', 'change': 'x'}],
            'build': {'system': 'make'}, 'verification': {'method': 'git diff', 'verified_by_agent_run': True},
            'sources': ['https://example.org/advisory']}
    card.update(changes)
    return card


def write(tmp_path, cards):
    path = tmp_path / 'cards.json'
    path.write_text(json.dumps(cards), encoding='utf-8')
    return path


def test_good_card_passes(tmp_path):
    assert corpus_check.check_catalog(write(tmp_path, [good_card()])) == []


@pytest.mark.parametrize('changes, text', [
    ({'license_spdx': 'GPL-3.0-only'}, 'license_spdx'),
    ({'old': {'ref': 'v1', 'commit': 'short'}}, 'old needs'),
    ({'changed_functions': []}, 'must name its changed functions'),
    ({'verification': {'method': 'recalled'}}, 'verification'),
    ({'id': []}, 'bad id'),
    ({'license_spdx': []}, 'license_spdx'),
    ({'kind': {}}, 'kind'),
    ({'build': {'system': []}}, 'build.system'),
    ({'kind': 'refactor-control', 'cve': [], 'changed_functions': []}, 'semantic_change'),
])
def test_bad_cards_are_flagged(tmp_path, changes, text):
    findings = corpus_check.check_catalog(write(tmp_path, [good_card(**changes)]))
    assert any(text in line for line in findings), findings


def test_duplicate_ids_are_flagged(tmp_path):
    assert any('duplicate id' in line for line in corpus_check.check_catalog(write(tmp_path, [good_card(), good_card()])))


@pytest.mark.parametrize('second_catalog', [
    'corpus/catalog/second.json',
    'tools/calibration/tier_r/catalogue/releases.json',
    'tools/calibration/tier_r/catalogue/cves.json',
])
def test_catalogues_share_card_ids(tmp_path, second_catalog):
    first = tmp_path / 'corpus/catalog/first.json'
    second = tmp_path / second_catalog
    for path, project in ((first, 'alpha'), (second, 'beta')):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps([good_card(project=project)]), encoding='utf-8')
        assert corpus_check.check_catalog(path) == []
    findings = corpus_check.check_all(tmp_path, compile_checks=False)
    assert len(findings) == 1
    assert all(part in findings[0] for part in ('duplicate id', 'demo-1-to-2', first.name, second.name))
    second.write_text(json.dumps([good_card(id='other-card', project='beta')]), encoding='utf-8')
    assert corpus_check.check_all(tmp_path, compile_checks=False) == []


def test_card_command_refuses_ambiguous_catalogue_before_build(tmp_path, monkeypatch, capsys):
    from tools.calibration.tier_r import cli

    root = tmp_path / 'repo'
    folder = root / 'corpus/catalog'
    folder.mkdir(parents=True)
    first, second = folder / 'first.json', folder / 'second.json'
    first.write_text(json.dumps([good_card(project='alpha')]), encoding='utf-8')
    second.write_text(json.dumps([good_card(project='beta')]), encoding='utf-8')
    monkeypatch.setattr(cli, 'REPO', root)
    assert cli.main(['catalogue-check']) == cli.FINDINGS
    problems = json.loads(capsys.readouterr().out)['problems']
    assert len(problems) == 1
    assert all(part in problems[0] for part in ('duplicate id', 'demo-1-to-2', first.name, second.name))
    monkeypatch.setattr(cli, 'probe', lambda: None)
    monkeypatch.setattr(cli.F, 'run_card', lambda *a, **kw: pytest.fail('ambiguous card reached the builder'))
    assert cli.main(['build-card', 'demo-1-to-2', '--store', str(tmp_path / 'store')]) == cli.USAGE
    error = json.loads(capsys.readouterr().out)['error']
    assert all(part in error for part in ('duplicate id', 'demo-1-to-2', first.name, second.name))

    second.write_text(json.dumps([good_card(id='other-card', project='beta')]), encoding='utf-8')
    assert cli.main(['catalogue-check']) == cli.OK
    assert json.loads(capsys.readouterr().out)['problems'] == []
    assert cli._card('demo-1-to-2').project == 'alpha'
    assert cli._card('other-card').project == 'beta'


def test_all_keeps_catalogue_findings_when_clang_is_blocked(tmp_path, monkeypatch, capsys):
    first = tmp_path / 'corpus/catalog/first.json'
    first.parent.mkdir(parents=True)
    second = first.with_name('second.json')
    for path in (first, second):
        path.write_text(json.dumps([good_card()]), encoding='utf-8')
    shutil.copytree(TEMPLATE, tmp_path / 'corpus/ours/demo/tiny')
    monkeypatch.setenv('PATH', '')
    assert corpus_check.main(['corpus_check.py', 'all', str(tmp_path)]) == 3
    lines = capsys.readouterr().out.splitlines()
    assert 'BLOCKED: clang is not installed' in lines
    assert any(all(part in line for part in ('duplicate id', first.name, second.name)) for line in lines)


def test_card_diagnostics_keep_both_relative_paths(tmp_path, monkeypatch, capsys):
    from tools.calibration.tier_r import cli

    # Both names fit in a filesystem component. Together with the ID they exceed 500 characters.
    root = tmp_path / 'checkout'
    folder = root / 'corpus/catalog'
    folder.mkdir(parents=True)
    ident = 'c' * 81
    paths = [folder / (letter * 205 + '.json') for letter in 'ab']
    for path in paths:
        path.write_text(json.dumps([good_card(id=ident)]), encoding='utf-8')
    monkeypatch.setattr(cli, 'REPO', root)
    monkeypatch.setattr(cli, 'probe', lambda: None)
    monkeypatch.setattr(cli.F, 'run_card', lambda *a, **kw: pytest.fail('ambiguous card reached the builder'))
    assert cli.main(['build-card', ident, '--store', str(tmp_path / 'store')]) == cli.USAGE
    message = json.loads(capsys.readouterr().out)['error']
    assert ident in message
    for path in paths:
        assert f'{path.relative_to(root).as_posix()}[0]' in message
    assert root.as_posix() not in message
    assert corpus_check.main(['corpus_check.py', 'all', str(root)]) == 1
    assert message in capsys.readouterr().out


@needs_clang
def test_template_suite_passes():
    assert corpus_check.check_suite(TEMPLATE) == []


@needs_clang
def test_authoring_mistakes_are_caught(tmp_path):
    copy = tmp_path / 'tiny'
    shutil.copytree(TEMPLATE, copy)
    suite = json.loads((copy / 'suite.json').read_text(encoding='utf-8'))
    suite['pairs'][0]['truth'][0]['label'] = 'changed'   # tiny_add is textually identical
    del suite['pairs'][0]['truth'][4]                    # tiny_new_only has no entry
    (copy / 'suite.json').write_text(json.dumps(suite), encoding='utf-8')
    text = (copy / 'v2' / 'tiny.c').read_text(encoding='utf-8')
    (copy / 'v2' / 'tiny.c').write_text('#include <stdio.h>\n' + text, encoding='utf-8')
    findings = '\n'.join(corpus_check.check_suite(copy))
    assert 'only freestanding headers' in findings
    assert 'labelled changed but the source text is identical' in findings
    assert 'without a truth entry' in findings


@needs_clang
def test_committed_corpus_is_valid():
    assert corpus_check.check_all(ROOT) == []


@needs_clang
def test_moved_means_another_file_and_same_label_needs_the_same_file(tmp_path):
    copy = tmp_path / 'tiny'
    shutil.copytree(TEMPLATE, copy)
    old = (copy / 'v1' / 'tiny.c').read_text(encoding='utf-8')
    (copy / 'v1' / 'extra.c').write_text('int32_t tiny_extra(int32_t x) { return x + 7; }\n', encoding='utf-8')
    (copy / 'v1' / 'extra.c').write_text('#include <stdint.h>\nint32_t tiny_extra(int32_t x) { return x + 7; }\n',
                                         encoding='utf-8')
    (copy / 'v2' / 'moved.c').write_text('#include <stdint.h>\nint32_t tiny_extra(int32_t x) { return x + 7; }\n',
                                         encoding='utf-8')
    assert old
    suite = json.loads((copy / 'suite.json').read_text(encoding='utf-8'))
    suite['pairs'][0]['truth'].append({'function': 'tiny_extra', 'label': 'moved'})
    (copy / 'suite.json').write_text(json.dumps(suite), encoding='utf-8')
    assert corpus_check.check_suite(copy) == []
    suite['pairs'][0]['truth'][-1]['label'] = 'same'
    (copy / 'suite.json').write_text(json.dumps(suite), encoding='utf-8')
    assert any('labelled same' in line for line in corpus_check.check_suite(copy))
