"""A display order is not consent to select a binary pair; dates cannot crash revision selection."""
from types import SimpleNamespace

import pytest
from kbc_k3_support import FixedClock, write_pair

from patchtrace.kbcorrelation import index
from patchtrace.kbcorrelation.service import KbService
from patchtrace.kbcorrelation.sources.cvrf import normal_timestamp
from patchtrace.kbcorrelation.store import KbcStoreError
from patchtrace.kbcorrelation.wiring import build_service
from patchtrace.sample import synthetic_pe


def pair(key, grade='A'):
    return SimpleNamespace(pair_id=key * 64, grade=grade)


def candidates(*pairs):
    return [SimpleNamespace(pairs=pairs)]


@pytest.mark.parametrize('reverse', [False, True])
def test_ambiguous_viable_pairs_require_explicit_selection(reverse):
    rows = [pair('a'), pair('b')]
    if reverse:
        rows.reverse()
    with pytest.raises(KbcStoreError, match='select one with --pair') as caught:
        KbService._pick_pair(candidates(*rows), None)
    assert caught.value.code == 'PT-KBC-INPUT'
    assert KbService._pick_pair(candidates(*rows), 'a' * 8).pair_id == 'a' * 64


def test_duplicate_observations_and_blocked_pairs_do_not_create_false_ambiguity():
    selected = pair('a')
    assert KbService._pick_pair(candidates(selected, selected, pair('b', 'X')), None) is selected
    assert KbService._pick_pair(candidates(pair('b', 'X')), None) is None


@pytest.mark.parametrize('value', ['0001-01-01T00:00:00+01:00', '9999-12-31T23:59:59-01:00'])
def test_release_dates_with_unrepresentable_utc_instants_are_rejected_and_legacy_rows_are_safe(value):
    assert normal_timestamp(value) is None
    assert index._instant(value) == index._instant(None)


def test_valid_offset_timestamp_keeps_original_text_and_compares_by_instant():
    value = '2099-02-01T00:30:00+01:00'
    assert normal_timestamp(value) == value
    assert index._instant(value) == index._instant('2099-01-31T23:30:00Z')


def test_local_pair_approval_is_bound_to_previewed_content(tmp_path):
    service = build_service(tmp_path / 'ws', clock=FixedClock())
    old, new = write_pair(tmp_path / 'inputs')
    destination = tmp_path / 'project'
    preview = service.import_pair('new', str(old), str(new), str(destination), dry_run=True)
    expected = preview.result['pair']['pair_id']
    new.write_bytes(synthetic_pe(2))
    with pytest.raises(KbcStoreError, match='changed after preview') as caught:
        service.import_pair('new', str(old), str(new), str(destination), expected_pair_id=expected)
    assert caught.value.code == 'PT-KBC-STALE'
    assert not destination.exists()
    new.write_bytes(synthetic_pe(1))
    result = service.import_pair('new', str(old), str(new), str(destination), expected_pair_id=expected)
    assert result.exit == 0
    assert result.result['pair']['pair_id'] == expected


def test_local_pair_preview_publishes_the_investigation_revision(tmp_path):
    from patchtrace.kbcorrelation.store import WorkspaceStore
    service = build_service(tmp_path / 'ws', clock=FixedClock())
    old, new = write_pair(tmp_path / 'inputs')
    fresh = service.import_pair('new', str(old), str(new), str(tmp_path / 'new-project'), dry_run=True)
    assert fresh.result['investigation_revision'] is None
    # A previous normal local project gives a real persisted investigation without any source transport.
    created = service.import_pair('new', str(old), str(new), str(tmp_path / 'existing-project'))
    inv = created.result['investigation_id']
    with WorkspaceStore(service.root) as ws:
        revision = ws.current_revision(inv).revision
    preview = service.import_pair(inv, str(old), str(new), str(tmp_path / 'unused'), dry_run=True)
    assert preview.result['investigation_revision'] == revision
    assert not (tmp_path / 'unused').exists()


def test_local_pair_commit_rejects_changed_revision_even_when_pair_identity_is_unchanged(tmp_path):
    import kbc_helpers as h
    from kbc_k1_support import import_fixture

    from patchtrace.kbcorrelation.store import WorkspaceStore
    service = build_service(tmp_path / 'ws', clock=FixedClock())
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json')
    with WorkspaceStore(service.root) as ws:
        ws.add_document(import_fixture('cvrf-2099-Feb.json'), raw)
    found = service.search('KB5099001')
    inv = found.result['investigation_id']
    old, new = write_pair(tmp_path / 'inputs')
    destination = tmp_path / 'project'
    preview = service.import_pair(inv, str(old), str(new), str(destination), dry_run=True)
    with WorkspaceStore(service.root) as ws:
        captured = ws.current_revision(inv).revision
    service.search('KB5099001', investigation=inv)
    with WorkspaceStore(service.root) as ws:
        current, history, decisions = ws.current_revision(inv), ws.revisions(inv), ws.decisions(inv)
    now = service.import_pair(inv, str(old), str(new), str(destination), dry_run=True)
    assert now.result['pair']['pair_id'] == preview.result['pair']['pair_id']
    assert current.revision > captured
    with pytest.raises(KbcStoreError) as caught:
        service.import_pair(inv, str(old), str(new), str(destination),
                            expected_pair_id=preview.result['pair']['pair_id'], expected_revision=captured)
    assert caught.value.code == 'PT-KBC-STALE'
    assert not destination.exists()
    with WorkspaceStore(service.root) as ws:
        assert ws.current_revision(inv) == current
        assert ws.revisions(inv) == history and ws.decisions(inv) == decisions
    accepted = service.import_pair(inv, str(old), str(new), str(destination),
                                   expected_pair_id=now.result['pair']['pair_id'],
                                   expected_revision=current.revision)
    assert accepted.exit == 0 and destination.is_dir()


@pytest.mark.parametrize('architecture', ['arm64', 'x86'])
@pytest.mark.parametrize('dry_run', [True, False])
def test_selected_known_product_architecture_cannot_label_incompatible_local_bytes(tmp_path, architecture,
                                                                                 dry_run):
    import kbc_helpers as h
    from kbc_k3_support import NOW

    from patchtrace.kbcorrelation.sources.importer import import_bytes
    from patchtrace.kbcorrelation.store import WorkspaceStore
    service = build_service(tmp_path / 'ws', clock=FixedClock())
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json').replace(b'ARM64', architecture.upper().encode())
    raw = raw.replace(b'"architecture": "arm64"', f'"architecture": "{architecture}"'.encode())
    with WorkspaceStore(service.root) as ws:
        ws.add_document(import_bytes(raw, now=NOW), raw)
    found = service.search('KB5099001')
    inv = found.result['investigation_id']
    scope = next(s['scope_id'] for s in found.result['scopes'] if s['architecture'] == architecture)
    service.search('KB5099001', investigation=inv, product=scope)
    old, new = write_pair(tmp_path / 'inputs')
    destination = tmp_path / 'project'
    with WorkspaceStore(service.root) as ws:
        before, history, decisions = ws.current_revision(inv), ws.revisions(inv), ws.decisions(inv)
        journal = tuple(ws.db.execute('SELECT * FROM journal'))
    with pytest.raises(KbcStoreError) as caught:
        service.import_pair(inv, str(old), str(new), str(destination), dry_run=dry_run)
    assert caught.value.code == 'PT-KBC-VERIFY'
    assert not destination.exists()
    with WorkspaceStore(service.root) as ws:
        assert ws.current_revision(inv) == before
        assert ws.revisions(inv) == history and ws.decisions(inv) == decisions
        assert tuple(ws.db.execute('SELECT * FROM journal')) == journal


def test_selected_unknown_product_architecture_remains_conservative_manual_pair(tmp_path):
    import kbc_helpers as h
    from kbc_k3_support import NOW

    from patchtrace.kbcorrelation.sources.importer import import_bytes
    from patchtrace.kbcorrelation.store import WorkspaceStore
    service = build_service(tmp_path / 'ws', clock=FixedClock())
    raw = h.read_fixture_bytes('cvrf-2099-Feb.json').replace(b'ARM64', b'Neutral')
    raw = raw.replace(b'"architecture": "arm64"', b'"architecture": "unknown"')
    with WorkspaceStore(service.root) as ws:
        ws.add_document(import_bytes(raw, now=NOW), raw)
    found = service.search('KB5099001')
    inv = found.result['investigation_id']
    scope = next(s['scope_id'] for s in found.result['scopes'] if s['architecture'] == 'unknown')
    service.search('KB5099001', investigation=inv, product=scope)
    old, new = write_pair(tmp_path / 'inputs')
    destination = tmp_path / 'project'
    preview = service.import_pair(inv, str(old), str(new), str(destination), dry_run=True)
    assert preview.result['pair']['grade'] == 'B'
    assert preview.result['pair']['lineage_state'] == 'user-asserted'
    assert preview.result['pair']['fix_boundary'] == 'unverified'
    result = service.import_pair(inv, str(old), str(new), str(destination),
                                 expected_pair_id=preview.result['pair']['pair_id'],
                                 expected_revision=preview.result['investigation_revision'])
    assert result.exit == 0 and result.result['pair']['grade'] == 'B'
    assert service._project_bundles(str(destination))[-1].scope_id == scope
