"""Fail-closed older Winbindex source admission; synthetic, no target execution/network."""
from __future__ import annotations

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from test_kbc_acquire_cli import SHA_O, ready as ready

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.acquire import row_for
from patchtrace.kbcorrelation.store import KbcStoreError

pytestmark = pytest.mark.usefixtures('no_sockets')
SHA = 'a' * 64
NAME = 'afd.sys'


def _body(kb=None, *, heading='BASE', version='10-22H2'):
    return {'sha256': SHA, 'file_name': NAME, 'version_key': version,
            'kb': kb, 'heading': heading, 'other_versions': []}


@pytest.mark.parametrize('reversed_order', [False, True])
def test_ambiguous_older_body_is_refused_in_either_source_order(reversed_order):
    base = _body()
    kb = _body('KB5030500', heading='update')
    rows = [kb, base] if reversed_order else [base, kb]
    # Original compatibility helper by itself still returns the first row.
    assert row_for(rows, SHA, NAME) is rows[0]
    with pytest.raises(KbcStoreError) as caught:
        row_for(rows, SHA, NAME, require_unique=True)
    assert caught.value.code == 'PT-KBC-INPUT'


def test_exact_duplicate_older_mappings_are_not_false_ambiguity():
    one = _body()
    assert row_for([one, dict(one)], SHA, NAME, require_unique=True) is one


def test_single_older_body_remains_usable():
    only = _body()
    assert row_for([only], SHA, NAME, require_unique=True) is only


def test_distinct_version_key_is_older_ambiguity_even_with_same_kb():
    with pytest.raises(KbcStoreError) as caught:
        row_for([_body(), _body(version='10-21H2')], SHA, NAME, require_unique=True)
    assert caught.value.code == 'PT-KBC-INPUT'


def test_selected_newer_body_uses_existing_resolver_target():
    rows = [_body(), _body('KB5030500', heading='update')]
    assert row_for(rows, SHA, NAME, target=('10-22H2', 'KB5030500')) is rows[1]


def test_missing_older_body_still_refuses():
    with pytest.raises(KbcStoreError) as caught:
        row_for([_body()], 'b' * 64, NAME, require_unique=True)
    assert caught.value.code == 'PT-KBC-INPUT'


def test_acquire_preview_does_not_plan_or_fetch_when_older_source_ambiguous(ready, monkeypatch):
    kb, server, investigation, flags, destination = ready
    original = wiring.WorkspaceFileIndex.rows_for

    def with_conflicting_old_body(index, file_name, key):
        rows = original(index, file_name, key)
        original_old = next(row for row in rows if row['sha256'] == SHA_O)
        competing = {**original_old, 'kb': 'KB5095999',
                     'heading': 'distinct older source body with same binary'}
        return [competing, *rows]

    monkeypatch.setattr(wiring.WorkspaceFileIndex, 'rows_for', with_conflicting_old_body)
    code, document, _stderr = kb('acquire', investigation, '--project', str(destination), *flags)
    assert code == 2 and 'PT-KBC-INPUT' in document['error']
    assert server.calls == [] and not destination.exists()
