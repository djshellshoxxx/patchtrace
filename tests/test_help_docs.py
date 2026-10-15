"""Invariants of the user help under docs/help/ (the reader-facing set, not the specs).

Every help page is reached from docs/help/README.md, every top-level CLI verb and every built GUI panel has a page,
and the troubleshooting page names every bundle and offline-install error code the code can raise. Titles and codes
are read from the code, so a renamed panel or a new code fails here until the help says so.
"""
from __future__ import annotations

import argparse
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
HELP = ROOT / 'docs' / 'help'
INDEX = HELP / 'README.md'
PAGE = re.compile(r'^\d{2}-[a-z0-9-]+\.md$')
LINK = re.compile(r'\]\(([^)#]+\.md)\)')


def _pages() -> list[Path]:
    return sorted(p for p in HELP.iterdir() if PAGE.fullmatch(p.name))


def _text(path: Path) -> str:
    return path.read_text(encoding='utf-8')


def _verbs() -> list[str]:
    from patchtrace import cli
    parser = cli._parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    return sorted(sub.choices)


def _built_panel_titles() -> list[str]:
    from patchtrace.panel_manifest import MANIFEST
    titles = []
    for entry in MANIFEST:
        try:
            spec = entry.load()
        except ModuleNotFoundError:
            continue  # not built yet: the manifest reserves the slot only
        titles.append(spec.title)
    return titles


def test_help_walk_is_not_vacuous():
    assert len(_pages()) >= 50, [p.name for p in _pages()]


@pytest.mark.parametrize('page', _pages(), ids=lambda p: p.name)
def test_every_help_page_is_linked_from_the_index(page):
    assert f']({page.name})' in _text(INDEX), f'{page.name} is not linked from docs/help/README.md'


def test_every_index_link_resolves():
    missing = [m for m in LINK.findall(_text(INDEX)) if not (HELP / m).is_file()]
    assert not missing, missing


@pytest.mark.parametrize('page', _pages(), ids=lambda p: p.name)
def test_no_capture_residue_in_help_pages(page):
    for line in _text(page).splitlines():
        assert line.strip() not in ('next', 'Worked for'), f'{page.name}: stray UI capture line'
        assert 'Worked for ' not in line, f'{page.name}: stray UI capture text'


@pytest.mark.parametrize('verb', _verbs())
def test_every_cli_verb_has_a_help_page(verb):
    heading = f'# `patchtrace {verb}`'
    pages = [p for p in _pages() if _text(p).splitlines()[:1] == [heading]]
    assert pages, f'no help page whose title is "{heading}"'


@pytest.mark.parametrize('title', _built_panel_titles())
def test_every_built_panel_has_a_help_page_with_its_title(title):
    hits = [p.name for p in _pages() if f'`{title}`' in _text(p) or _text(p).startswith(f'# {title}')]
    assert hits, f'no help page names the built panel "{title}" by its UI title'


def test_glossary_and_troubleshooting_pages_exist():
    names = [p.name for p in _pages()]
    assert any(n.endswith('-glossary.md') for n in names), names
    assert any(n.endswith('-troubleshooting.md') for n in names), names


def test_troubleshooting_names_every_bundle_and_offline_code():
    from patchtrace import backend_bundle
    page = next(p for p in _pages() if p.name.endswith('-troubleshooting.md'))
    text = _text(page)
    codes = set(backend_bundle.CODES) | {'PT-OFFLINE', 'PT-CANCEL'}
    missing = sorted(c for c in codes if f'`{c}`' not in text)
    assert not missing, missing
