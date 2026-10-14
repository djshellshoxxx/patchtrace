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
    ({'kind': 'refactor-control', 'cve': [], 'changed_functions': []}, 'semantic_change'),
])
def test_bad_cards_are_flagged(tmp_path, changes, text):
    findings = corpus_check.check_catalog(write(tmp_path, [good_card(**changes)]))
    assert any(text in line for line in findings), findings


def test_duplicate_ids_are_flagged(tmp_path):
    assert any('duplicate id' in line for line in corpus_check.check_catalog(write(tmp_path, [good_card(), good_card()])))


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
