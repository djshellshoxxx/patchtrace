"""Conservative selected newer Winbindex source identity; synthetic, no target execution."""
from __future__ import annotations

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from test_kbc_acquire_cli import NET, SHA_N, ready as ready

from patchtrace.kbcorrelation import wiring
from patchtrace.kbcorrelation.acquire import row_for, target_row_membership
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.store import KbcStoreError

pytestmark = pytest.mark.usefixtures('no_sockets')
SHA = 'a' * 64
NAME = 'afd.sys'
TARGET = ('10-22H2', 'KB5030500')


def _row(*, heading='native', version='10-22H2', other_versions=(), kb='KB5030500'):
    return {'sha256': SHA, 'file_name': NAME, 'version_key': version,
            'kb': kb, 'heading': heading, 'other_versions': list(other_versions)}


@pytest.mark.parametrize('reverse', [False, True])
def test_conflicting_native_selected_newer_rows_refuse_in_both_orders(reverse):
    native = _row()
    different = _row(heading='different native source body')
    rows = [different, native] if reverse else [native, different]
    with pytest.raises(KbcStoreError) as caught:
        row_for(rows, SHA, NAME, target=TARGET)
    assert caught.value.code == 'PT-KBC-INPUT'


@pytest.mark.parametrize('reverse', [False, True])
def test_conflicting_copied_selected_newer_rows_refuse_in_both_orders(reverse):
    copied = _row(version='10-21H2', other_versions=('10-22H2',))
    different = _row(heading='different copied source body', version='10-21H2',
                     other_versions=('10-22H2',))
    rows = [different, copied] if reverse else [copied, different]
    with pytest.raises(KbcStoreError) as caught:
        row_for(rows, SHA, NAME, target=TARGET)
    assert caught.value.code == 'PT-KBC-INPUT'


def test_identical_newer_source_rows_are_admissible():
    native = _row()
    assert row_for([native, dict(native)], SHA, NAME, target=TARGET) is native


def test_native_body_retains_priority_over_nonidentical_copied_body():
    copied = _row(heading='copied old', version='10-21H2', other_versions=('10-22H2',))
    native = _row(heading='native')
    assert row_for([copied, native], SHA, NAME, target=TARGET) is native


def test_unselected_kb_row_does_not_create_false_ambiguity():
    native = _row()
    unrelated = _row(heading='other KB', kb='KB5000000')
    assert row_for([unrelated, native], SHA, NAME, target=TARGET) is native


def test_acquire_preview_refuses_conflicting_newer_source_without_transport_or_project(ready, monkeypatch):
    kb, server, investigation, flags, destination = ready
    # Select the same exact newer KB/version body as the resolver, not the
    # first record with this SHA (which could be a BASE or propagated copy).
    service = KbService(kb.workspace, kb.env)
    _revision, resolutions, _skipped, _missing = service._resolve_pairs(investigation, flags[1], [NET])
    target = target_row_membership(service._pick_pair(resolutions, None))
    original = wiring.WorkspaceFileIndex.rows_for

    def conflicting_newer(index, file_name, key):
        rows = original(index, file_name, key)
        newer = row_for(rows, SHA_N, NET, target=target)
        conflict = {**newer, 'heading': 'different same-window newer source body'}
        return [conflict, *rows]

    monkeypatch.setattr(wiring.WorkspaceFileIndex, 'rows_for', conflicting_newer)
    code, document, _stderr = kb('acquire', investigation, '--project', str(destination), *flags)
    assert code == 2 and 'PT-KBC-INPUT' in document['error']
    assert server.calls == [] and not destination.exists()
